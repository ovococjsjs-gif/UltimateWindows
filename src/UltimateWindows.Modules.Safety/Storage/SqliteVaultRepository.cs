using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Safety.Storage;

/// <summary>
/// Компактный SQLite-репозиторий журнала транзакций с поддержкой авто-сжатия файла БД (auto_vacuum = INCREMENTAL).
/// </summary>
public sealed class SqliteVaultRepository
{
    private readonly string _dbPath;
    private readonly string _connectionString;

    public SqliteVaultRepository(string vaultDirectory)
    {
        Directory.CreateDirectory(vaultDirectory);
        _dbPath = Path.Combine(vaultDirectory, "vault.db");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();

        InitializeSchema();
    }

    public string DatabaseFilePath => _dbPath;

    public long GetDatabaseSizeBytes()
    {
        long total = 0;
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var candidate = _dbPath + suffix;
            if (File.Exists(candidate))
            {
                total += new FileInfo(candidate).Length;
            }
        }

        return total;
    }

    private void InitializeSchema()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            PRAGMA auto_vacuum = INCREMENTAL;
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS vault_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
                session_id TEXT PRIMARY KEY,
                domain INTEGER NOT NULL,
                friendly_title TEXT NOT NULL,
                friendly_summary TEXT NOT NULL,
                technical_details TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                blob_expires_at_utc TEXT NULL,
                is_pinned INTEGER NOT NULL DEFAULT 0,
                is_reverted INTEGER NOT NULL DEFAULT 0,
                reverted_at_utc TEXT NULL,
                total_stored_bytes INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS deltas (
                delta_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                sequence_order INTEGER NOT NULL,
                target_kind INTEGER NOT NULL,
                target_path TEXT NOT NULL,
                previous_state_json TEXT NULL,
                new_state_json TEXT NULL,
                blob_sha256 TEXT NULL,
                original_size_bytes INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES transactions(session_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_deltas_session ON deltas(session_id, sequence_order);
            CREATE INDEX IF NOT EXISTS idx_deltas_blob ON deltas(blob_sha256);
            CREATE INDEX IF NOT EXISTS idx_tx_created ON transactions(created_at_utc);
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task SaveTransactionAsync(TransactionRecord record, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var tx = await conn.BeginTransactionAsync(ct).ConfigureAwait(false);

        await using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = (SqliteTransaction)tx;
            cmd.CommandText = """
                INSERT INTO transactions (
                    session_id, domain, friendly_title, friendly_summary, technical_details,
                    created_at_utc, blob_expires_at_utc, is_pinned, is_reverted, reverted_at_utc, total_stored_bytes
                ) VALUES (
                    $id, $domain, $title, $summary, $tech,
                    $created, $expires, $pinned, $reverted, $revertedAt, $bytes
                );
                """;
            cmd.Parameters.AddWithValue("$id", record.SessionId.ToString("D"));
            cmd.Parameters.AddWithValue("$domain", (int)record.Domain);
            cmd.Parameters.AddWithValue("$title", record.FriendlyTitle);
            cmd.Parameters.AddWithValue("$summary", record.FriendlySummary);
            cmd.Parameters.AddWithValue("$tech", record.TechnicalDetails);
            cmd.Parameters.AddWithValue("$created", record.CreatedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$expires", record.BlobExpiresAtUtc.HasValue
                ? record.BlobExpiresAtUtc.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)
                : DBNull.Value);
            cmd.Parameters.AddWithValue("$pinned", record.IsPinned ? 1 : 0);
            cmd.Parameters.AddWithValue("$reverted", record.IsReverted ? 1 : 0);
            cmd.Parameters.AddWithValue("$revertedAt", record.RevertedAtUtc.HasValue
                ? record.RevertedAtUtc.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)
                : DBNull.Value);
            cmd.Parameters.AddWithValue("$bytes", record.TotalStoredBytes);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        foreach (var delta in record.Deltas)
        {
            await using var deltaCmd = conn.CreateCommand();
            deltaCmd.Transaction = (SqliteTransaction)tx;
            deltaCmd.CommandText = """
                INSERT INTO deltas (
                    delta_id, session_id, sequence_order, target_kind, target_path,
                    previous_state_json, new_state_json, blob_sha256, original_size_bytes
                ) VALUES (
                    $did, $sid, $seq, $kind, $path, $prev, $next, $sha, $origBytes
                );
                """;
            deltaCmd.Parameters.AddWithValue("$did", delta.DeltaId.ToString("D"));
            deltaCmd.Parameters.AddWithValue("$sid", delta.SessionId.ToString("D"));
            deltaCmd.Parameters.AddWithValue("$seq", delta.SequenceOrder);
            deltaCmd.Parameters.AddWithValue("$kind", (int)delta.TargetKind);
            deltaCmd.Parameters.AddWithValue("$path", delta.TargetPath);
            deltaCmd.Parameters.AddWithValue("$prev", (object?)delta.PreviousStateJson ?? DBNull.Value);
            deltaCmd.Parameters.AddWithValue("$next", (object?)delta.NewStateJson ?? DBNull.Value);
            deltaCmd.Parameters.AddWithValue("$sha", (object?)delta.BlobSha256 ?? DBNull.Value);
            deltaCmd.Parameters.AddWithValue("$origBytes", delta.OriginalSizeBytes);
            await deltaCmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    public async Task<TransactionRecord?> GetTransactionByIdAsync(Guid sessionId, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM transactions WHERE session_id = $id LIMIT 1;";
        cmd.Parameters.AddWithValue("$id", sessionId.ToString("D"));

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return null;
        }

        var header = ReadTransactionHeader(reader);
        await reader.CloseAsync().ConfigureAwait(false);

        var deltas = await LoadDeltasAsync(conn, sessionId, ct).ConfigureAwait(false);
        return header with { Deltas = deltas };
    }

    public async Task<IReadOnlyList<TransactionRecord>> GetRecentTransactionsAsync(int limit = 100, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        var headers = new List<TransactionRecord>();

        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM transactions ORDER BY created_at_utc DESC LIMIT $limit;";
            cmd.Parameters.AddWithValue("$limit", limit);

            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                headers.Add(ReadTransactionHeader(reader));
            }
        }

        var result = new List<TransactionRecord>(headers.Count);
        foreach (var h in headers)
        {
            var deltas = await LoadDeltasAsync(conn, h.SessionId, ct).ConfigureAwait(false);
            result.Add(h with { Deltas = deltas });
        }

        return result;
    }

    public async Task MarkRevertedAsync(Guid sessionId, DateTimeOffset revertedAtUtc, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE transactions
            SET is_reverted = 1, reverted_at_utc = $revAt
            WHERE session_id = $id;
            """;
        cmd.Parameters.AddWithValue("$id", sessionId.ToString("D"));
        cmd.Parameters.AddWithValue("$revAt", revertedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task SetPinnedAsync(Guid sessionId, bool isPinned, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE transactions SET is_pinned = $pin WHERE session_id = $id;";
        cmd.Parameters.AddWithValue("$id", sessionId.ToString("D"));
        cmd.Parameters.AddWithValue("$pin", isPinned ? 1 : 0);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Возвращает кандидатов на очистку файловых блобов в порядке от самых старых к новым (только не закрепленные пользователем).
    /// </summary>
    public async Task<IReadOnlyList<(Guid SessionId, DateTimeOffset CreatedAtUtc, DateTimeOffset? ExpiresAtUtc, string BlobSha256)>>
        GetUnpinnedBlobReferencesOldestFirstAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT t.session_id, t.created_at_utc, t.blob_expires_at_utc, d.blob_sha256
            FROM deltas d
            INNER JOIN transactions t ON t.session_id = d.session_id
            WHERE d.blob_sha256 IS NOT NULL AND t.is_pinned = 0
            ORDER BY t.created_at_utc ASC;
            """;

        var list = new List<(Guid, DateTimeOffset, DateTimeOffset?, string)>();
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var sid = Guid.Parse(reader.GetString(0));
            var created = DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            DateTimeOffset? expires = reader.IsDBNull(2)
                ? null
                : DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            var sha = reader.GetString(3);
            list.Add((sid, created, expires, sha));
        }

        return list;
    }

    /// <summary>
    /// Проверяет, удерживает ли хотя бы одна ЗАКРЕПЛЕННАЯ (is_pinned = 1) транзакция данный SHA-256 блоб.
    /// </summary>
    public async Task<bool> IsBlobReferencedByPinnedTransactionAsync(string sha256Hex, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT COUNT(1)
            FROM deltas d
            INNER JOIN transactions t ON t.session_id = d.session_id
            WHERE d.blob_sha256 = $sha AND t.is_pinned = 1;
            """;
        cmd.Parameters.AddWithValue("$sha", sha256Hex);
        var count = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture);
        return count > 0;
    }

    /// <summary>
    /// Отвязывает удаленный файловый блоб от незакрепленных дельт и запускает сжатие файла БД (incremental_vacuum),
    /// сохраняя при этом историю транзакций и все записи отката реестра!
    /// </summary>
    public async Task DetachBlobFromUnpinnedTransactionsAndCompactAsync(string sha256Hex, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                UPDATE deltas
                SET blob_sha256 = NULL
                WHERE blob_sha256 = $sha
                  AND session_id IN (SELECT session_id FROM transactions WHERE is_pinned = 0);

                UPDATE transactions
                SET total_stored_bytes = 1024
                WHERE is_pinned = 0
                  AND session_id NOT IN (
                      SELECT DISTINCT session_id FROM deltas WHERE blob_sha256 IS NOT NULL
                  )
                  AND total_stored_bytes > 4096;

                PRAGMA incremental_vacuum;
                """;
            cmd.Parameters.AddWithValue("$sha", sha256Hex);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    public async Task<(int ActiveCount, int RevertedCount)> GetTransactionCountsAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT
                COALESCE(SUM(CASE WHEN is_reverted = 0 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN is_reverted = 1 THEN 1 ELSE 0 END), 0)
            FROM transactions;
            """;
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return (reader.GetInt32(0), reader.GetInt32(1));
        }

        return (0, 0);
    }

    public async Task SavePolicyAsync(VaultQuotaPolicy policy, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(policy);
        await SaveSettingAsync("quota_policy", json, ct).ConfigureAwait(false);
    }

    public VaultQuotaPolicy LoadPolicyOrDefault()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT setting_value FROM vault_settings WHERE setting_key = 'quota_policy' LIMIT 1;";
        var raw = cmd.ExecuteScalar() as string;
        if (!string.IsNullOrWhiteSpace(raw))
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<VaultQuotaPolicy>(raw);
                if (parsed is not null)
                {
                    return parsed;
                }
            }
            catch
            {
                // Возвращаем дефолт при некорректном JSON
            }
        }

        return new VaultQuotaPolicy();
    }

    public async Task SaveSettingAsync(string key, string value, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO vault_settings (setting_key, setting_value)
            VALUES ($k, $v)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value;
            """;
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<string?> GetSettingAsync(string key, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT setting_value FROM vault_settings WHERE setting_key = $k LIMIT 1;";
        cmd.Parameters.AddWithValue("$k", key);
        return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
    }

    private static async Task<IReadOnlyList<StateDeltaRecord>> LoadDeltasAsync(
        SqliteConnection conn,
        Guid sessionId,
        CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT delta_id, session_id, sequence_order, target_kind, target_path,
                   previous_state_json, new_state_json, blob_sha256, original_size_bytes
            FROM deltas
            WHERE session_id = $sid
            ORDER BY sequence_order ASC;
            """;
        cmd.Parameters.AddWithValue("$sid", sessionId.ToString("D"));

        var list = new List<StateDeltaRecord>();
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            list.Add(new StateDeltaRecord(
                DeltaId: Guid.Parse(reader.GetString(0)),
                SessionId: Guid.Parse(reader.GetString(1)),
                SequenceOrder: reader.GetInt32(2),
                TargetKind: (StateTargetKind)reader.GetInt32(3),
                TargetPath: reader.GetString(4),
                PreviousStateJson: reader.IsDBNull(5) ? null : reader.GetString(5),
                NewStateJson: reader.IsDBNull(6) ? null : reader.GetString(6),
                BlobSha256: reader.IsDBNull(7) ? null : reader.GetString(7),
                OriginalSizeBytes: reader.GetInt64(8)));
        }

        return list;
    }

    private static TransactionRecord ReadTransactionHeader(SqliteDataReader reader)
    {
        var sessionId = Guid.Parse(reader.GetString(reader.GetOrdinal("session_id")));
        var domain = (SystemDomain)reader.GetInt32(reader.GetOrdinal("domain"));
        var title = reader.GetString(reader.GetOrdinal("friendly_title"));
        var summary = reader.GetString(reader.GetOrdinal("friendly_summary"));
        var tech = reader.GetString(reader.GetOrdinal("technical_details"));
        var created = DateTimeOffset.Parse(
            reader.GetString(reader.GetOrdinal("created_at_utc")),
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind);

        var expiresOrd = reader.GetOrdinal("blob_expires_at_utc");
        DateTimeOffset? expires = reader.IsDBNull(expiresOrd)
            ? null
            : DateTimeOffset.Parse(reader.GetString(expiresOrd), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

        var pinned = reader.GetInt32(reader.GetOrdinal("is_pinned")) != 0;
        var reverted = reader.GetInt32(reader.GetOrdinal("is_reverted")) != 0;

        var revOrd = reader.GetOrdinal("reverted_at_utc");
        DateTimeOffset? revertedAt = reader.IsDBNull(revOrd)
            ? null
            : DateTimeOffset.Parse(reader.GetString(revOrd), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

        var totalBytes = reader.GetInt64(reader.GetOrdinal("total_stored_bytes"));

        return new TransactionRecord(
            SessionId: sessionId,
            Domain: domain,
            FriendlyTitle: title,
            FriendlySummary: summary,
            TechnicalDetails: tech,
            CreatedAtUtc: created,
            BlobExpiresAtUtc: expires,
            IsPinned: pinned,
            IsReverted: reverted,
            RevertedAtUtc: revertedAt,
            TotalStoredBytes: totalBytes,
            Deltas: Array.Empty<StateDeltaRecord>());
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken ct)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        return conn;
    }
}
