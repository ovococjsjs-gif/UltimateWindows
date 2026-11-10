using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class BrowserVaultGuardTests
{
    [Theory]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Login Data")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Login Data For Account")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Microsoft\Edge\User Data\Default\Web Data")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Local State")]
    [InlineData(@"C:\Users\Alex\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\logins.json")]
    [InlineData(@"C:\Users\Alex\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\key4.db")]
    [InlineData(@"C:\Users\Alex\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\formhistory.sqlite")]
    public void EvaluatePath_StrictlyProtectsPasswordsAndAutofill(string protectedPath)
    {
        var decision = BrowserVaultGuard.EvaluatePath(protectedPath);

        Assert.Equal(VaultPathDecision.ProtectedCredentialsOrAutofill, decision);
        Assert.False(BrowserVaultGuard.CanDeleteDuringStandardCleanup(protectedPath));
        Assert.Throws<InvalidOperationException>(() => BrowserVaultGuard.ThrowIfProtected(protectedPath));
    }

    [Theory]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Sessions\Session_13345")]
    [InlineData(@"C:\Users\Alex\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default\storage\default\moz-extension+++1234\idb\data.sqlite")]
    public void EvaluatePath_ProtectsActiveSessionsAndExtensions(string extensionOrSessionPath)
    {
        var decision = BrowserVaultGuard.EvaluatePath(extensionOrSessionPath);

        Assert.Equal(VaultPathDecision.ProtectedSessionOrExtension, decision);
        Assert.False(BrowserVaultGuard.CanDeleteDuringStandardCleanup(extensionOrSessionPath));
    }

    [Theory]
    [InlineData(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_0001a2")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\data_1")]
    [InlineData(@"C:\Users\Alex\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\js\index")]
    [InlineData(@"C:\Users\Alex\AppData\Local\Mozilla\Firefox\Profiles\abcd.default-release\cache2\entries\9A8B7C")]
    [InlineData(@"C:\Users\Alex\AppData\Local\NVIDIA\DXCache\shader01.bin")]
    public void EvaluatePath_AllowsSafeDisposableCaches(string cachePath)
    {
        var decision = BrowserVaultGuard.EvaluatePath(cachePath);

        Assert.Equal(VaultPathDecision.SafeDisposableCache, decision);
        Assert.True(BrowserVaultGuard.CanDeleteDuringStandardCleanup(cachePath));
    }
}
