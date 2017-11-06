using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Numerics;
using System.Threading;
using System.IO;
using System.Collections;

namespace RabinConsole
{
     public class Rabin
    {


        /// <summary>
        /// Generates a 512 bit number
        /// </summary>
        /// <returns>Returns a 512 bit Biginteger value</returns>
        public static BigInteger GenerateNumbers()
        {
            //generate a 512 bit array (64 byte)
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[64];
            //fill the array with a cryptographically strong sequence of random values
            rng.GetBytes(bytes);
            //create a number from the array
            BigInteger number = new BigInteger(bytes);
            //check if negative
            if (number.Sign < 0)
            {
                number = GenerateNumbers();
            }

            return number;
        }

        /// <summary>
        /// Generates an 1024 bit private key
        /// </summary>
        /// <returns>Returns a Biginteger prime value where the value mod 4 = 3 </returns>
        public static BigInteger GeneratePrivateKey()
        {
            BigInteger key = GenerateNumbers();

            //to check if the number generated is prime
            while (!MillerRabinTest(key))
            {
                key = GenerateNumbers();
            }

            //check if the number generated mod 4 == 3
            if (key % 4 != 3)
            {
                key = GeneratePrivateKey();
            } 

            return key;
        }

        /// <summary>
        /// Generates an open key
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns>Returns a Biginteger value</returns>
        public static BigInteger GenerateOpenKey(BigInteger p, BigInteger q)
        {
            BigInteger n = p * q;
            return n;
        }

        #region Encryption

        /// <summary>
        /// Encrypts the blocks of bytes of the specified file stream (128 bit blocks)
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns>Returns an encrypted bytes array</returns>
        public static byte[] EncryptSreamBytes(FileStream stream, BigInteger p, BigInteger q, List<int> blockSizeList)
        {
            //create a list for arrays
            List<byte> outputBytes = new List<byte>();
            int offset = 0;
            stream.Position = 0;

            //write the filestream to 128 bit arrays
            while (true)
            {
                byte[] buffer = new byte[16];
                stream.Position = offset;
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0)
                {
                    break;
                }
                else
                {
                    BigInteger t = new BigInteger(buffer);

                    //encrypt the bit array
                    buffer = Encrypt(p, q, buffer);

                    blockSizeList.Add(buffer.Length);

                    //add the array to the collection
                    outputBytes.AddRange(buffer);
                }

                //set an offset
                offset += bytesRead;
            }
            return outputBytes.ToArray();
        }


        /// <summary>
        /// Ecrypts the specified bytes array with p and q private keys
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <param name="arr">Returns an Encrypted bytes array</param>
        /// <returns></returns>
        public static byte[] Encrypt(BigInteger p, BigInteger q, byte[] arr)
        {
            BigInteger n = GenerateOpenKey(p, q);

            //encrypt
            BigInteger bivalue = new BigInteger(arr);
            bivalue = MX(bivalue);

            BigInteger result = BigInteger.ModPow(bivalue, 2, n);

            return result.ToByteArray();
        }

        #endregion

        #region Decryption

        /// <summary>
        /// Decrypts the blocks of bytes of the specified file stream (128 bit blocks)
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="p"></param>
        /// <param name="q">Returns a decrypted bytes array</param>
        /// <returns></returns>
        public static byte[] DecruptStreamBytes(FileStream stream, BigInteger p, BigInteger q, List<int> blockSizeList)
        {
            //create a list for arrays
            List<byte> outputBytes = new List<byte>();
            int offset = 0;
            stream.Position = 0;
            int i = 0;

            while (i != blockSizeList.Count)
            {
                byte[] buffer = new byte[blockSizeList.ElementAt(i)];
                stream.Position = offset;
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    break;
                }
                else
                {

                    //select a correct decrypted value
                    BigInteger BIntbuffer = new BigInteger(buffer);
                    BigInteger m1, m2, m3, m4;

                    Decrypt(BIntbuffer, p, q, out m1, out m2, out m3, out m4);

                    BigInteger[] arr = new BigInteger[] {m1, m2, m3, m4 };

                    var result = arr.Where(m => m.ToString().EndsWith("0000")).First();
                    result = MXR(result);

                    buffer = result.ToByteArray();

                    //add the array to the collection
                    outputBytes.AddRange(buffer);
                }

                //set an offset
                offset += bytesRead;
                i++;
            }
            return outputBytes.ToArray();
        }

        /// <summary>
        /// Decrypts a bloc of bytes (128 bit block)
        /// </summary>
        /// <param name="c"></param>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <param name="m1"></param>
        /// <param name="m2"></param>
        /// <param name="m3"></param>
        /// <param name="m4"></param>
        public static void Decrypt(BigInteger c, BigInteger p, BigInteger q, out BigInteger m1, out BigInteger m2, out BigInteger m3, out BigInteger m4)
        {
            BigInteger n = GenerateOpenKey(p, q);

            //Chinees theorem for mp and mq
            BigInteger mp = BigInteger.ModPow(c, ((p + 1) / 4), p);
            BigInteger mq = BigInteger.ModPow(c, ((q + 1) / 4), q);

            BigInteger yp, yq;

            //yp and yq via Extended Euclidean algorithm
            ExtendedEuclidean(p, q, out yp, out yq);

            //calculate m1, m2, m3, m4
            m1 = (yp * p * mq + yq * q * mp) % n;
            while (m1 < 0)
            {
                m1 += n;
            }
            m2 = n - m1;
            m3 = (yp * p * mq - yq * q * mp) % n;
            while (m3 < 0)
            {
                m3 += n;
            }
            m4 = n - m3;
            return;
        }



        /// <summary>
        /// Extended Euclidean algorithm
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <param name="x"></param>
        /// <param name="y"></param>
        static void ExtendedEuclidean(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {

            BigInteger r = b, q = 0, x0 = 1, y0 = 0, x1 = 0, y1 = 1;
            bool reverse = false;

            if (a < b) //if a less than b, switch them
            {
                BigInteger temp = a;
                a = b;
                b = temp;
                reverse = true;
            }

            while (r > 1)
            {
                r = a % b;
                q = a / b;
                x = x0 - q * x1;
                y = y0 - q * y1;
                x0 = x1;
                y0 = y1;
                x1 = x;
                y1 = y;
                a = b;
                b = r;

            }

            if (reverse)
            {
                x = y1;
                y = x1;
            }
            else
            {
                x = x1;
                y = y1;
            }

            return;
        }

        #endregion


        #region Corre Methods
        //
        /// <summary>
        /// Hash fucntion
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Returns a Biginteger number with last 4 nulls</returns>
        static BigInteger MX(BigInteger value)
        {
            return value * 10000;
        }

        /// <summary>
        /// Reverse HAsh function
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Returns a Biginteger number without last 4 nulls</returns>
        static BigInteger MXR(BigInteger value)
        {
            return value / 10000;
        }

        /// <summary>
        /// Cheks if a nuber is prime
        /// </summary>
        /// <param name="Number"></param>
        /// <returns>Returns True if the number is possibly prime. Othervise False</returns>
        public static bool MillerRabinTest(BigInteger Number)
        {
            if (Number <= 2)
                throw new Exception("The number is less than 3");

            if (BigInteger.ModPow(Number, 1, 2) == 0)
                return false;

            int X = 1;
            BigInteger pow = 2;
            do
            {
                if (X < pow * 2 && pow >= X)
                    break;
                pow *= 2;
                X++;
            } while (true);

            BigInteger S, T;

            Step2(Number, out T, out S);

            //A cycle
            for (int i = 0; i < X; i++)
            {
                bool flagtoCycleA = false;
                BigInteger a = Rand(Number - 1);
                BigInteger x = BigInteger.ModPow(a, T, Number);
                if (x == 1 || x == Number - 1)
                    continue;
                //цикл Б
                for (int k = 0; k < (S - 1); k++)
                {
                    x = BigInteger.ModPow(x, 2, Number);
                    if (x == 1)
                        return false;
                    if (x == Number - 1)
                    {
                        flagtoCycleA = true;
                        break;
                    }


                }
                if (flagtoCycleA)
                    continue;
                return false;

            }

            return true;
        }


        /// <summary>
        /// Second step to find S and T
        /// </summary>
        /// <param name="P">A number</param>
        /// <param name="T">Remainder</param>
        /// <param name="S">The power of 2</param>
        static void Step2(BigInteger P, out BigInteger T, out BigInteger S)
        {
            BigInteger Pminus = P - 1;

            int Some2Pow = 0;

            do
            {
                if (Pminus % 2 == 0)
                {
                    Some2Pow++;
                    Pminus /= 2;
                }
                else
                {
                    T = Pminus;
                    S = Some2Pow;
                    return;
                }

            } while (true);

        }

        /// <summary>
        /// Gets rundom value from 1 to p
        /// </summary>
        /// <param name="p"></param>
        /// <returns>Returns a Biginteger value</returns>
        static BigInteger Rand(BigInteger p)
        {

            BigInteger result;
            string str = "";
            bool flag = true;

            int[] pio = (p + "").ToCharArray().Select(k => int.Parse(k + "")).ToArray();

            for (int i = 0; i < pio.Length; i++)
            {

                int x;
                if (flag)
                {
                    x = rnd.Next(1, pio[i] + 1);
                    if (x < pio[i])
                        flag = false;

                }
                else
                {
                    x = rnd.Next(1, 10);
                }

                str += x;
            }

            result = BigInteger.Parse(str);
            return result;
        }

        static Random rnd = new Random();
        
        #endregion

    }
}
