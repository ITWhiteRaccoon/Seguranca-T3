using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Spectre.Console;
using TextCopy;

namespace Seguranca_T3;

public class Program
{
    private static readonly BigInteger _p = BigInteger.Parse(
        "0B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
        NumberStyles.HexNumber);

    private static readonly BigInteger _g = BigInteger.Parse(
        "0A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
        NumberStyles.HexNumber);

    //Testando com os dados do Marcelo, descobri que os valores estavam sendo lidos errado, considerando o primeiro bit como sinal
    private static readonly BigInteger _a = BigInteger.Parse(
        //a que criei
        //"045C772344A83A45B5D45AF04B56222CB35B596F477EA0544C74E580E8162B04EF2508DABA2DDAB09129142463888F475E930A56A33AB4E3C1C1BD127DE7341CA",

        //a do Marcelo
        "030d0fe7f631de71f4aa542791ed4f16032427b30b575c89c90716f42e14039ee8c56d708fb6392c722325c093726fadb6a1e188e5b805aa3f4b12b1d2db7a3a9b1c11dcf5f3fcf37525b219efec12e2a0f82d1ff5497ef9204b54c07a691e738f06419dc8100f478ce189b769df3c173db9428072d65606bb37989abd8f31ac",
        NumberStyles.HexNumber);

    private static readonly BigInteger _A = BigInteger.Parse(
        //A que gerei a partir de a
        //"45C3F234391ED8952CD2C716C46D2B39D22155EB2D3BC522B17F5A790877BBBD536AD3409657957A78DABC5ECB335E048101AA5340595E853B443074F653433DC80C850D6DCA13C13B805FA3A45E24C2C9B7468F3D62C33947CFD176C8DE7713C03DF1F9598E3E09099AEB49CC00662E6EC1FB7355CCCC58A309972FF957CAF4",

        //A que gerei a partir do a do Marcelo (modifiquei partes do código que lidam com bits, precisei especificar
        //que era big endian e em alguns casos adicionar 0 antes para o primeiro bit não ser lido como sinal)
        "2346A9E987A0E80DC9525FC230A7309F5DDC729708A62F70A207B90FFBB422ED3F55D5962F85A9AFDB39FAB16E4D7D632BDEFA739438A46089C73827614A53A6EA048ED4761A9D053F13FE65A398E75744F12AB38C898EC0FE44A3F5ADABB0AD8E6CA4C68DC70B5AAF309E3D4A1ABC570B125553D9C03722C431C8D7A7BEE774",
        NumberStyles.HexNumber);

    private static readonly BigInteger _B = BigInteger.Parse(
        //B dado pelo professor
        //"01C3EB24A247FD5E63D291BEFD4A7F2C33EF40D2EDAF9A494A33A7E87AB081A6E45817FE0A730BACB2033A9FC9C21F21BB147597F95B76F42297E71B0FDDB717CE70C75A7D539F857A8A24ABF5AC00B0F6DF0D906A3397487DCB56356F3A2A764AB91310F279EBBADE7200B77126EBB30E1883B9BBA57F1F2C034467BE2EFFCE",

        //B do Marcelo
        "10E16402D232A9675EC44224D070D08EBACB583813F64CDC738DAA1ADBA07F6E8598951C1D92A0775A5C323BD3765EF85196D9ADA2D014855D20F684693F53BDBC46E880DB874270412549FC02BB78348C7ACDD04E7D349291C9528A8E3B5030C05C6B46C596F6C69625EA57834DD1419C73A326FA1FE4C381DE61646503E224",
        NumberStyles.HexNumber);

    private static readonly BigInteger _S = BigInteger.Parse(
        //S que gerei
        //"01FE4DACD4977D1026CB66F4E909F3729",

        //S que gerei com os valores do Marcelo 
        "1FFD67B6098FFC3C46B4FF66CDFF47FC",
        NumberStyles.HexNumber);

    private const string _msg1 =
        //Mensagem que recebi do professor
        //"82093EC847F37FF13921204AAEB59D7A2E07F931E428DE47D9EC0D85FFBB0EDEAC26A4F5C14DF003B0FE34D04B4EA4F96523DAC2A6EEF3F27B14FFFA3593397C49875E390E386ECD9B5CB3F432F1122CA4B88C1D3DF5C6C551C019FBD990DEC97EF231F70AD34DA27EE0E6493B48AB86";

        //Mensagem do Marcelo (Decifrada para: Muito bom Marcel. Agora inverte esta frase e manda ela de volta cifrada. Abs. Agora com senha certa.)
        "7DF2DC1C0E9FB66EA5249C508B0B832AB8811F1472CD75F374F372161256F1F8F15BD7F3E0DCA9C14BF92C6FBBA9283BBC8A5691B8469EFC3A0A70F330978DFB798E67009CBF75CA882776E0374313139A9517608A8D069AA03FF1E388288ACCA92F3ED6A1DF19F5ABE6BAF640E44CE5FC10218773172E80E9528A486378C655";

    //Mensagem do Marcelo invertida e cifrada
    //"4ECD4D0C8319D0C0C39AB865815702B3750DD6CC20B96C9EEC554150471CAFAA64BBD23E96ECFD1E8B6E57A18929951F9B795E8C58F5A7DC4C0A7DEC7884238FB5A55F59A6132A18DB90FC71E89D2AFDB323883B62BFE391F36471BEF33F9B928C51532CB21F4CAAF97635EAD4D260968B1DCADE613559AFEC6D101E111A1955";
    
    
    //Para gerar o valor A, segui os passos do documento. Estava funcionando, eu errei na parte de converter para string
    //então acabei enviando o valor errado ao professor.
    private static void GeraValorA()
    {
        AnsiConsole.MarkupLine("\n[green]a:[/]");
        AnsiConsole.WriteLine(_a.ToString("X"));//usando 'a' pronto

        var A = BigInteger.ModPow(_g, _a, _p);
        //gera 'A' (depois de gerar salvei na variável estática no início do código)
        var AStr = A.ToString("X");
        ClipboardService.SetText(AStr);
        AnsiConsole.MarkupLine("\n[green]A:[/] (should be on your clipboard now)");
        AnsiConsole.WriteLine(AStr);
    }
    
    private static void CalculaS(BigInteger B)
    {
        var V = BigInteger.ModPow(B, _a, _p);
        using var sha = SHA256.Create();
        
        //Tive que indicar que 'V' era big endian antes de computar o hash
        var S = sha.ComputeHash(V.ToByteArray(isBigEndian: true));
        
        //Transformei os bytes do hash em uma string hexadecimal
        var SStr = BitConverter.ToString(S).Replace("-", null)[..32];
        
        //Adicionei o valor resultante na área de transferência do computador, além de printar
        ClipboardService.SetText(SStr);
        AnsiConsole.MarkupLine("[green]S:[/]");
        AnsiConsole.WriteLine(SStr);
    }

    private static void DecifraMsg(string msg, BigInteger S)
    {
        //Para ler o valor hex da mensagem, foi preciso converter a string para um BigInt e usá-lo como array de bytes
        //Aqui além de indicar que o array de bytes era big endian, tive que adicionar um 0 na frente como bit mais significativo
        var iv = BigInteger.Parse($"0{msg[..32]}", NumberStyles.HexNumber).ToByteArray(isBigEndian: true);
        var textoCifrado = BigInteger.Parse(msg[32..], NumberStyles.HexNumber).ToByteArray(isBigEndian: true);

        //Configuro o AES
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Key = S.ToByteArray(isBigEndian: true);
        aes.IV = iv;

        var decifrador = aes.CreateDecryptor(aes.Key, aes.IV);
        //Com o AES configurado com a chave e o IV, decifro o texto
        var texto = Encoding.UTF8.GetString(decifrador.TransformFinalBlock(textoCifrado, 0, textoCifrado.Length));
        AnsiConsole.WriteLine($"Texto decifrado: {texto}");

        //Inverto o texto e envio para ser cifrado
        CifraMsg(new string(texto.Reverse().ToArray()));
    }
    
    private static void CifraMsg(string msg)
    {
        //Leio o texto como bytes
        var bytes = Encoding.UTF8.GetBytes(msg);

        //Configuro o AES
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Key = _S.ToByteArray(isBigEndian: true);//Tive que indicar que era big endian
        //Já existe uma função que gera o IV
        aes.GenerateIV();

        var cifrador = aes.CreateEncryptor(aes.Key, aes.IV);
        //Cifrei o texto e converti de array de bytes para texto hexadecimal
        var texto = BitConverter.ToString(cifrador.TransformFinalBlock(bytes, 0, bytes.Length)).Replace("-", null);
        //Converti também o IV
        var iv = BitConverter.ToString(aes.IV).Replace("-", null);
        
        //Imprimo no console e também adiciono na área de transferência o IV + texto cifrado
        ClipboardService.SetText(iv + texto);
        AnsiConsole.WriteLine($"Texto cifrado: {iv}{texto}");
    }

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
                CalculaS(_B);
                break;
            case 3:
                DecifraMsg(_msg1, _S);
                break;
        }
    }
}