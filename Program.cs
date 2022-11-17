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
    private static readonly BigInteger _p = BigInteger.Parse(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
        NumberStyles.HexNumber);

    private static readonly BigInteger _g = BigInteger.Parse(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
        NumberStyles.HexNumber);

    private static readonly BigInteger _a = BigInteger.Parse(
        "45C772344A83A45B5D45AF04B56222CB35B596F477EA0544C74E580E8162B04EF2508DABA2DDAB09129142463888F475E930A56A33AB4E3C1C1BD127DE7341CA",
        NumberStyles.HexNumber);

    private static BigInteger _B = BigInteger.Parse(
        "01C3EB24A247FD5E63D291BEFD4A7F2C33EF40D2EDAF9A494A33A7E87AB081A6E45817FE0A730BACB2033A9FC9C21F21BB147597F95B76F42297E71B0FDDB717CE70C75A7D539F857A8A24ABF5AC00B0F6DF0D906A3397487DCB56356F3A2A764AB91310F279EBBADE7200B77126EBB30E1883B9BBA57F1F2C034467BE2EFFCE",
        NumberStyles.HexNumber);

    private static BigInteger _S = BigInteger.Parse(
        "1FE4DACD4977D1026CB66F4E909F3729",
        NumberStyles.HexNumber);

    private static string _msg =
        "73819C658B473CAD224CCA61DE9AE1D45EC373CC5DA0048DA4F0B2806B0153E4426D421A7061E1804DDA0D9A49A6D76ED84B9248C02F1B1D2EC46ADA23F516210354A84BD545D0C1D0B08503A319CCDFD8EDB17891442630CB312E9C5A70AAF3F947485C41970A672D54E8B49222A219";

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
                //var BStr = AnsiConsole.Prompt(new TextPrompt<string>("Digite o valor de B: "));
                //var B = BigInteger.Parse(BStr, NumberStyles.HexNumber);
                CalculaS();
                break;
            case 3:
                DecifraMsg();
                break;
        }
    }

    public static void DecifraMsg()
    {
        DecifraMsg(_msg, _S);
    }

    public static void DecifraMsg(string msg, BigInteger S)
    {
        var iv = BigInteger.Parse(msg[..32], NumberStyles.HexNumber).ToByteArray();
        var textoCifrado = BigInteger.Parse(msg[32..], NumberStyles.HexNumber).ToByteArray();

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Key = S.ToByteArray();
        aes.IV = iv;

        var decifrador = aes.CreateDecryptor(aes.Key, aes.IV);
        var texto = Encoding.UTF8.GetString(decifrador.TransformFinalBlock(textoCifrado, 0, textoCifrado.Length));
        AnsiConsole.MarkupLine($"Texto decifrado: [bold]{texto}[/]");
    }

    public static void CalculaS()
    {
        CalculaS(_B);
    }

    public static void CalculaS(BigInteger B)
    {
        var V = BigInteger.ModPow(B, _a, _p);
        using var sha = SHA256.Create();
        var S = sha.ComputeHash(V.ToByteArray());
        var SStr = BitConverter.ToString(S).Replace("-", null)[..32];
        //S = 1FE4DACD4977D1026CB66F4E909F3729
        ClipboardService.SetText(SStr);
        AnsiConsole.MarkupLine("[green]S:[/]");
        AnsiConsole.WriteLine(SStr);
    }

    public static void GeraValorA()
    {
        var aStr = BitConverter.ToString(_a.ToByteArray()).Replace("-", null);
        AnsiConsole.MarkupLine("\n[green]a:[/]");
        AnsiConsole.WriteLine(aStr);

        var A = BigInteger.ModPow(_g, _a, _p);
        var AStr = BitConverter.ToString(A.ToByteArray()).Replace("-", null);
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