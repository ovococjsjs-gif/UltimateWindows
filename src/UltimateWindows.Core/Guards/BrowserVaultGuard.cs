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
        "/glcache/",
        "/dawngraphitecache/",
        "/dawnwebgpucache/",
        "/graphitedawncache/",
        "/application cache/",
        "/media cache/",
        "/component_crx_cache/",
        "/extensions_crx_cache/",
        "/browsermetrics/",
        "/optguideondevicemodel/",
        "/cache2/",
        "/jumplistcache/",
        "/offlinecache/",
        "/crash reports/",
        "/crashes/",
        "/minidumps/",
        "/datareporting/archived/",
        "/saved-telemetry-pings/"
    ];

    /// <summary>
    /// Признаки того, что путь лежит в данных браузера или встроенного в программу браузера.
    /// Внутри таких папок очистке разрешён только кэш; всё остальное — личные данные.
    /// </summary>
    private static readonly string[] BrowserAreaMarkers =
    [
        "/google/chrome",
        "/microsoft/edge",
        "/yandex/yandexbrowser",
        "/bravesoftware/",
        "/vivaldi/",
        "/opera software/",
        "/chromium/user data",
        "/mozilla/",
        "/thunderbird/",
        "/librewolf/",
        "/waterfox/",
        "/moonchild productions/",
        "/the browser company/",
        "/avast software/browser/",
        "/avg/browser/",
        "/coccoc/",
        "/centbrowser/",
        "/thorium/",
        "/tor browser/",
        "/ebwebview/",
        "/user data/default/",
        "/user data/profile ",
        "/user data/guest profile/",
        "/user data/system profile/"
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
    /// Возвращает true, если путь лежит в данных браузера (профиль, общая папка данных, встроенный браузер программы).
    /// Здесь правилам очистки разрешён только кэш — см. <see cref="CanDeleteDuringStandardCleanup"/>.
    /// </summary>
    public static bool IsInsideBrowserProfileArea(string? candidatePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            return false;
        }

        var normalized = candidatePath.Trim().Replace('\\', '/').ToLowerInvariant();
        if (!normalized.EndsWith('/'))
        {
            normalized += "/";
        }

        foreach (var marker in BrowserAreaMarkers)
        {
            if (normalized.Contains(marker, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Возвращает true, если путь указывает на защищенные пароли, ключи шифрования, формы автозаполнения, сессии или расширения.
    /// </summary>
    public static bool IsProtectedPersonalData(string? candidatePath)
    {
        var decision = EvaluatePath(candidatePath);
        return decision is VaultPathDecision.ProtectedCredentialsOrAutofill
            or VaultPathDecision.ProtectedSessionOrExtension;
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
