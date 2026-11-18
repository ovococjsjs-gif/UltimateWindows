namespace UltimateWindows.Core.Models;

// Числа хранятся в SQLite. Только Applied разрешает автоматическое обратное действие.
public enum StepState { Planned = 0, Started = 1, Applied = 2, Unconfirmed = 3 }

public sealed record StepReceipt(string Label, StepState State, string Detail = "")
{
    public string StatusText => State switch
    {
        StepState.Planned => "не начато",
        StepState.Started => "начато, итог не записан — проверьте объект",
        StepState.Applied => "выполнено",
        _ => "не подтверждено" + (Detail.Length > 0 ? $" ({Detail})" : "")
    };
}

/// <summary>Ответ платформы и наличие квитанции — разные факты. При ошибке записи
/// после успешного действия нельзя ни повторить его, ни обещать автоматический откат.</summary>
public sealed record StepExecution(bool Applied, bool ReceiptSaved, string Detail);
