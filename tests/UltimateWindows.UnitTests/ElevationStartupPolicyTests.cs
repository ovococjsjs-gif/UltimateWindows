using UltimateWindows.Core.Elevation;
using Xunit;

namespace UltimateWindows.UnitTests;

/// <summary>
/// Правила запроса прав администратора при запуске программы.
/// </summary>
public sealed class ElevationStartupPolicyTests
{
    [Fact]
    public void RequestsElevationByDefault_WhenStartedWithoutAdministratorRights()
    {
        Assert.True(ElevationStartupPolicy.ShouldRequestElevationOnStartup([], isAlreadyElevated: false));
        Assert.True(ElevationStartupPolicy.ShouldRequestElevationOnStartup(["--some-other-switch"], isAlreadyElevated: false));
    }

    [Fact]
    public void DoesNotRequestElevation_WhenAlreadyElevated_OptedOut_OrAlreadyRelaunched()
    {
        Assert.False(ElevationStartupPolicy.ShouldRequestElevationOnStartup([], isAlreadyElevated: true));

        // Пользователь явно попросил обычный режим
        Assert.False(ElevationStartupPolicy.ShouldRequestElevationOnStartup(["--no-elevate"], isAlreadyElevated: false));
        Assert.False(ElevationStartupPolicy.ShouldRequestElevationOnStartup(["--NO-ELEVATE "], isAlreadyElevated: false));

        // Перезапуск уже был, но права получить не удалось: второй попытки быть не должно, иначе возникнет цикл
        Assert.False(ElevationStartupPolicy.ShouldRequestElevationOnStartup(
            [ElevationStartupPolicy.ElevatedRelaunchSwitch], isAlreadyElevated: false));
    }

    [Fact]
    public void RelaunchArguments_KeepUserArguments_DropServiceSwitches_AndMarkTheRelaunch()
    {
        var relaunch = ElevationStartupPolicy.BuildRelaunchArguments(
            ["--profile", "C:\\Users\\User\\my profile.yaml", "--no-elevate", "--elevated-relaunch"]);

        Assert.Equal(
            new[] { "--profile", "C:\\Users\\User\\my profile.yaml", ElevationStartupPolicy.ElevatedRelaunchSwitch },
            relaunch);

        // Перезапущенный экземпляр больше не просит права, даже если их так и не получил
        Assert.False(ElevationStartupPolicy.ShouldRequestElevationOnStartup(relaunch, isAlreadyElevated: false));

        Assert.Equal(
            new[] { ElevationStartupPolicy.ElevatedRelaunchSwitch },
            ElevationStartupPolicy.BuildRelaunchArguments([]));
    }
}
