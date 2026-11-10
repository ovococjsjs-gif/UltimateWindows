using UltimateWindows.Core.Enums;

namespace UltimateWindows.Core.Guards;

/// <summary>
/// Жесткий защитный фильтр (Hardcoded Safety Invariant), гарантирующий сохранение паролей,
/// автозаполнения форм, ключей шифрования и расширений браузеров при любой очистке.
/// </summary>
public static class BrowserVaultGuard
{
    private static readonly string[] ProtectedCredentialOrAutofillFileNames =
    [
        "login data",
        "login data for account",
        "login data-journal",
        "web data",
        "web data-journal",
        "ya passman data",
        "ya passman data-journal",
        "ya autofill data",
        "ya autofill data-journal",
        "local state",
        "logins.json",
        "logins-backup.json",
        "key3.db",
        "key4.db",
        "formhistory.sqlite",
        "formhistory.sqlite-wal",
        "formhistory.sqlite-shm",
        "bookmarks",
        "bookmarks.bak",
        "places.sqlite",
        "places.sqlite-wal",
        "cert9.db",
        "preferences",
        "secure preferences",
        "prefs.js"
    ];

    private static readonly string[] ProtectedSessionOrExtensionMarkers =
    [
        "/local extension settings/",
        "/sync extension settings/",
        "/managed extension settings/",
        "/indexeddb/chrome-extension_",
        "/storage/default/moz-extension+++",
        "/sessions/session_",
        "/sessions/tabs_",
        "/network/cookies",
        "/cookies.sqlite",
        "/extension cookies"
    ];

    private static readonly string[] SafeCacheMarkers =
    [
        "/cache/cache_data/",
        "/code cache/",
        "/gpucache/",
        "/dawncache/",
        "/grshadercache/",
        "/shadercache/",
        "/shader-cache/",
        "/service worker/cachestorage/",
        "/service worker/scriptcache/",
        "/crashpad/reports/",
        "/cache2/entries/",
        "/cache2/doomed/",
        "/startupcache/",
        "/thumbnails/",
        "/dxcache/",
        "/glcache/"
    ];

    /// <summary>
    /// Классифицирует путь к файлу профиля браузера или кэша.
    /// </summary>
    public static VaultPathDecision EvaluatePath(string? candidatePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            return VaultPathDecision.NeutralRequiresExplicitRule;
        }

        var normalized = candidatePath.Trim().Replace('\\', '/').ToLowerInvariant();
        var fileName = GetNormalizedFileName(normalized);

        foreach (var protectedFile in ProtectedCredentialOrAutofillFileNames)
        {
            if (string.Equals(fileName, protectedFile, StringComparison.Ordinal))
            {
                return VaultPathDecision.ProtectedCredentialsOrAutofill;
            }
        }

        foreach (var marker in ProtectedSessionOrExtensionMarkers)
        {
            if (normalized.Contains(marker, StringComparison.Ordinal))
            {
                return VaultPathDecision.ProtectedSessionOrExtension;
            }
        }

        foreach (var cacheMarker in SafeCacheMarkers)
        {
            if (normalized.Contains(cacheMarker, StringComparison.Ordinal))
            {
                return VaultPathDecision.SafeDisposableCache;
            }
        }

        return VaultPathDecision.NeutralRequiresExplicitRule;
    }

    /// <summary>
    /// Возвращает true только если путь гарантированно не затрагивает пароли, формы, сессии и расширения.
    /// </summary>
    public static bool CanDeleteDuringStandardCleanup(string? candidatePath)
    {
        var decision = EvaluatePath(candidatePath);
        return decision == VaultPathDecision.SafeDisposableCache;
    }

    /// <summary>
    /// Бросает исключение безопасности при любой попытке удалить защищенный файл паролей/форм.
    /// </summary>
    public static void ThrowIfProtected(string candidatePath)
    {
        var decision = EvaluatePath(candidatePath);
        if (decision is VaultPathDecision.ProtectedCredentialsOrAutofill
            or VaultPathDecision.ProtectedSessionOrExtension)
        {
            throw new InvalidOperationException(
                $"Блокировка безопасности BrowserVaultGuard: путь '{candidatePath}' содержит защищенные пользовательские данные ({decision}) и не может быть удален.");
        }
    }

    private static string GetNormalizedFileName(string normalizedPath)
    {
        var trimmed = normalizedPath.TrimEnd('/');
        var idx = trimmed.LastIndexOf('/');
        return idx >= 0 ? trimmed[(idx + 1)..] : trimmed;
    }
}
