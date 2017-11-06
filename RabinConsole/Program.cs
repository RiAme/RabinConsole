using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.IO;

namespace RabinConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            //Byte block size for decryption
            List<int> blockSizeList = new List<int>();

            BigInteger p = Rabin.GeneratePrivateKey();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Private key p:\n {0}", p);

            BigInteger q = Rabin.GeneratePrivateKey();
            Console.WriteLine("Private key q:\n {0}", q);

            BigInteger n = Rabin.GenerateOpenKey(p, q);
            Console.WriteLine("Open key n:\n {0}", n);
            Console.WriteLine();
            Console.ResetColor();
            Console.WriteLine("Private key p length: {0} bit", (p.ToByteArray().Length * 8));
            Console.WriteLine("Private key q length: {0} bit", (q.ToByteArray().Length * 8));
            Console.WriteLine("Open key n length: {0} bit", (n.ToByteArray().Length*8));
            Console.WriteLine();

            //encrypt text
            Console.WriteLine("Enter a path to *.txt file to be encrypted:");
            string ToBeEncrypted = Console.ReadLine(); 
            string EncryptedFile = "..\\debug\\encrypted.txt";

            byte[] textdata = null;

            using (FileStream stream = new FileStream(ToBeEncrypted, FileMode.Open, FileAccess.Read))
            {
                textdata = Rabin.EncryptSreamBytes(stream, p, q, blockSizeList);              
            }

            //write encrypted text to file
            File.WriteAllBytes(EncryptedFile, textdata);

            Console.WriteLine();
            Console.WriteLine("Path to the encrypted file: {0}", Path.GetFullPath(EncryptedFile));
            Console.WriteLine();
            Console.WriteLine("Encrypted content:\n");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(textdata, 0, textdata.Length));
            Console.ResetColor();
            Console.WriteLine();

            //decrypt text
            string DecryptedFile = "..\\debug\\decrypted.txt";

            byte[] decrypted = null;
            using (FileStream stream = new FileStream(EncryptedFile, FileMode.Open, FileAccess.Read))
            {
                decrypted = Rabin.DecruptStreamBytes(stream, p, q, blockSizeList);
            }

            //write encrypted text to file
            File.WriteAllBytes(DecryptedFile, decrypted);

            Console.WriteLine("Path to the decrypted file: {0}", Path.GetFullPath(DecryptedFile));
            Console.WriteLine();
            Console.WriteLine("Decrypted content:\n");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(decrypted, 0, decrypted.Length));
            Console.ResetColor();

            Console.ReadKey();
        }
    }
}
