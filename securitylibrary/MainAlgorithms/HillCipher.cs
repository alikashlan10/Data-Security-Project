using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int mod(int x, int m) { return (x % m + m) % m; }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count); //key matrix mxm
            //covert key to 2D list
            List<List<int>> key2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                    tmp.Add(key[i * m + j]);
                key2d.Add(tmp);
            }
            List<List<int>> key2dInv = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                    tmp.Add(0);
                key2dInv.Add(tmp);
            }
            //invert key matrix (check 2x2 or 3x3)
            int det;

            if (m == 2)
            {
                //a d
                key2dInv[0][0] = mod(key2d[1][1], 26);
                key2dInv[1][1] = mod(key2d[0][0], 26);
                //b c
                key2dInv[0][1] = mod(-1 * key2d[0][1], 26);
                key2dInv[1][0] = mod(-1 * key2d[1][0], 26);
                //find determinant
                det = (key2d[0][0] * key2d[1][1]) - (key2d[0][1] * key2d[1][0]);
                det = mod(det, 26);
                //find multiplicative inverse of the determinant working modulo 26.
                int detMltInv = 1;
                // search for number b which{ b*det = 1 mod 26 && b<26 }
                for (; detMltInv < 26; detMltInv++)
                    if (mod(detMltInv * det, 26) == 1) break;
                if(detMltInv == 26)
                    throw new InvalidAnlysisException();
                //multiply it with the cofactors
                for (int i = 0; i < m; i++)
                    for (int j = 0; j < m; j++)
                        key2dInv[i][j] = mod(key2dInv[i][j] * detMltInv, 26);
                for (int i = 0; i < m; i++)
                    for (int j = 0; j < m; j++)
                        key2d[i][j] = key2dInv[i][j];
            }
            else
            {
                //mtx3x3 inv
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        int a = key2d[mod(i - 1, 3)][mod(j - 1, 3)];
                        int b = key2d[mod(i - 1, 3)][mod(j + 1, 3)];
                        int c = key2d[mod(i + 1, 3)][mod(j - 1, 3)];
                        int d = key2d[mod(i + 1, 3)][mod(j + 1, 3)];
                        key2dInv[i][j] = a * d - b * c;
                        key2dInv[i][j] *= (int)Math.Pow(-1, i + j);
                    }
                }

                //find determinant
                det = key2d[0][0] * key2dInv[0][0] - key2d[0][1] * key2dInv[0][1] + key2d[0][2] * key2dInv[0][2];
                det = mod(det, 26);
                //find multiplicative inverse of the determinant working modulo 26.
                int detMltInv = 1;
                // search for number b which{ b*det = 1 mod 26 && b<26 }
                for (; detMltInv < 26; detMltInv++)
                    if (mod(detMltInv * det, 26) == 1) break;
                //multiply it with the cofactors
                for (int i = 0; i < m; i++)
                    for (int j = 0; j < m; j++)
                        key2dInv[i][j] = mod((int)Math.Pow(-1, i + j)*key2dInv[i][j] * detMltInv, 26);
                for (int i = 0; i < m; i++)
                    for (int j = 0; j < m; j++)
                        key2d[i][j] = key2dInv[j][i];
            }


            int n = cipherText.Count / m; //number of columns in plain/cipher text 
            //covert cipherText to 2D list
            List<List<int>> cipherText2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < n; j++)
                    tmp.Add(cipherText[j * m + i]);
                cipherText2d.Add(tmp);
            }
            //create 2D list for plainText
            List<List<int>> plainText2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < n; j++)
                    tmp.Add(0);
                plainText2d.Add(tmp);
            }
            //decrypt
            //key2d = key2dInv;
            for (int i = 0; i < m; i++)
            {
                for (int k = 0; k < n; k++)
                {
                    for (int j = 0; j < m; j++)
                        plainText2d[i][k] += (key2d[i][j] * cipherText2d[j][k]);
                    plainText2d[i][k] %= 26;
                }
            }
            //covert plainText to 1D list
            List<int> plainText = new List<int>(new int[cipherText.Count]);
            for (int i = 0; i < m; i++)
                for (int j = 0; j < n; j++)
                    plainText[j * m + i] = plainText2d[i][j];
            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count); //key matrix mxm
            //covert key to 2D list
            List<List<int>> key2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                    tmp.Add(key[i * m + j]);
                key2d.Add(tmp);
            }

            int n = plainText.Count / m; //number of columns in plain/cipher text 
            //covert plainText to 2D list
            List<List<int>> plainText2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < n; j++)
                    tmp.Add(plainText[j * m + i]);
                plainText2d.Add(tmp);
            }
            //create 2D list for cipherText
            List<List<int>> cipherText2d = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < n; j++)
                    tmp.Add(0);
                cipherText2d.Add(tmp);
            }
            //encrypt
            for (int i = 0; i < m; i++)
            {
                for (int k = 0; k < n; k++)
                {
                    for (int j = 0; j < m; j++)
                        cipherText2d[i][k] += (key2d[i][j] * plainText2d[j][k]);
                    cipherText2d[i][k] %= 26;
                }
            }
            //covert cipherText to 1D list
            List<int> cipherText = new List<int>(new int[plainText.Count]);
            for (int i = 0; i < m; i++)
                for (int j = 0; j < n; j++)
                    cipherText[j * m + i] = cipherText2d[i][j];
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
