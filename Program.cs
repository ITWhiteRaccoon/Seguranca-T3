using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Spectre.Console;
using TextCopy;

// ReSharper disable InconsistentNaming

namespace Seguranca_T3;

public class Program
{
    public static BigInteger p = BigInteger.Parse(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
        NumberStyles.HexNumber);

    public static BigInteger g = BigInteger.Parse(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
        NumberStyles.HexNumber);

    public static BigInteger a = BigInteger.Parse(
        "45C772344A83A45B5D45AF04B56222CB35B596F477EA0544C74E580E8162B04EF2508DABA2DDAB09129142463888F475E930A56A33AB4E3C1C1BD127DE7341CA",
        NumberStyles.HexNumber);

    public static void Main(string[] args)
    {
        var opcao = AnsiConsole.Prompt(new SelectionPrompt<int>()
            .Title("Escolha uma opção:")
            .AddChoices(1, 2, 3, 0).UseConverter(i =>
            {
                return i switch
                {
                    1 => "1. Gerar a e A",
                    2 => "2. Calcular S",
                    3 => "3. Decifrar mensagem",
                    0 => "0. Sair",
                    _ => "Erro"
                };
            })
        );

        switch (opcao)
        {
            case 0:
                return;
            case 1:
                GeraValorA();
                break;
            case 2:
                var BStr = AnsiConsole.Prompt(new TextPrompt<string>("Digite o valor de B: "));
                BStr = BStr.Remove(' ').Remove('-').Remove('_');
                var B = BigInteger.Parse(BStr, NumberStyles.HexNumber);
                CalculaS(B);
                break;
        }

        GeraValorA();
    }

    public static byte[] CalculaS(BigInteger B)
    {
        var V = BigInteger.ModPow(B, a, p);
        using var sha = SHA256.Create();
        var S = sha.ComputeHash(V.ToByteArray());
        return S;
    }

    public static void GeraValorA()
    {
        var aStr = ToHexString(a);
        AnsiConsole.MarkupLine("\n[green]a:[/]");
        AnsiConsole.WriteLine(aStr);

        var A = BigInteger.ModPow(g, a, p);
        var AStr = ToHexString(A);
        ClipboardService.SetText(AStr);
        AnsiConsole.MarkupLine("\n[green]A:[/] (should be on your clipboard now)");
        AnsiConsole.WriteLine(AStr);
    }

    public static string ToHexString(BigInteger value)
    {
        var str = value.ToString("X8");
        var sb = new StringBuilder();
        sb.Append(str[..8]);
        for (var i = 8; i < str.Length; i += 8)
        {
            sb.Append($"-{str[i..(i + 8)]}");
        }

        return sb.ToString();
    }
}