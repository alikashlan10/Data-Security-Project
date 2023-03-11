using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            key = key.ToLower();
            cipherText = cipherText.ToLower();

            List<char> l = new List<char>(26);
            for (int i = 0; i < key.Length; i++)
            {
                if (!l.Contains(key[i]))
                    l.Add(key[i]);
            }
            for (int i = 97; i < 123; i++)
            {
                if (!l.Contains((char)i))
                {
                    if ((l.Contains('i') && (char)i == 'j') || (l.Contains('j') && (char)i == 'i'))
                        continue;
                    else
                        l.Add((char)i);
                }
            }
            char[,] matrix = new char[5, 5];

            int cntr = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    matrix[row, col] = l[cntr];
                    cntr++;
                }
            }



            /////////////////////////////////

            string plainText = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {

                int r1 = 0, r2 = 0, c1 = 0, c2 = 0;
                char ch1 = cipherText[i];
                char ch2 = cipherText[i + 1];

                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (matrix[r, c] == ch1)
                        {
                            r1 = r;
                            c1 = c;
                        }
                        else if (matrix[r, c] == ch2)
                        {
                            r2 = r;
                            c2 = c;
                        }
                    }
                }
                // row row
                if (r1 == r2)
                {
                    plainText += matrix[r1, (c1 + 4) % 5];
                    plainText += matrix[r2, (c2 + 4) % 5];
                }
                //col col
                else if (c1 == c2)
                {
                    plainText += matrix[(r1 + 4) % 5, c1];
                    plainText += matrix[(r2 + 4) % 5, c2];
                }
                // normal
                else
                {
                    plainText += matrix[r1, c2];
                    plainText += matrix[r2, c1];
                }
            }
            // x at end
            int extra = (plainText.Length % 2);
            if (plainText.EndsWith("x"))
            {
                extra++;
            }
            plainText = plainText.Substring(0, plainText.Length - extra);


            string PlainX = plainText;
            int shift = 0;
            for (int i = 1; i < plainText.Length - 1; i++)
            {
                if (PlainX[i] == 'x' && PlainX[i - 1] == PlainX[i + 1] && (i % 2 != 0))
                {
                    plainText = plainText.Remove(i - shift, 1);
                    shift++;
                }
            }
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            List<char> l = key.Distinct().ToList();
            for (int i = 97; i < 123; i++)
            {
                if (!l.Contains((char)i))
                {
                    if ((l.Contains('i') && (char)i == 'j') || (l.Contains('j') && (char)i == 'i'))
                        continue;
                    else
                        l.Add((char)i);
                }
            }
            char[,] matrix = new char[5, 5];
            int index = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    matrix[row, col] = l[index++];
                }
            }

            // x if repeated
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }

            // x if odd
            if (plainText.Length % 2 != 0)
            {
                plainText = plainText + 'x';
            }

            string cipherText = "";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char ch1 = plainText[i];
                char ch2 = plainText[i + 1];
                int r1 = 0, r2 = 0, c1 = 0, c2 = 0;

                // matrix pos
                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (matrix[r, c] == ch1)
                        {
                            r1 = r;
                            c1 = c;
                        }
                        else if (matrix[r, c] == ch2)
                        {
                            r2 = r;
                            c2 = c;
                        }
                    }
                }
                // row row
                if (r1 == r2)
                {
                    cipherText += matrix[r1, (c1 + 1) % 5];
                    cipherText += matrix[r2, (c2 + 1) % 5];
                }
                //col col
                else if (c1 == c2)
                {
                    cipherText += matrix[(r1 + 1) % 5, c1];
                    cipherText += matrix[(r2 + 1) % 5, c2];
                }
                // normal
                else
                {
                    cipherText += matrix[r1, c2];
                    cipherText += matrix[r2, c1];
                }
            }
            return cipherText;
        }
    }
}