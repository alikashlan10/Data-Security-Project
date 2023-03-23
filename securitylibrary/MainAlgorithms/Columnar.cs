using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int row = 0;
            int col = 0;

            for (int i = 1; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    col = i;
                    row = plainText.Length / col;
                }
            }

            char[,] plainMatrix = new char[row, col];
            char[,] cipherMatrix = new char[row, col];

            int plcount = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (plcount <= plainText.Length)
                    {
                        plainMatrix[i, j] = plainText[plcount];
                        plcount++;
                    }
                }
            }
            int cicount = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    if (cicount <= cipherText.Length)
                    {
                        cipherMatrix[j, i] = cipherText[cicount];
                        cicount++;
                    }
                }
            }

            List<int> key = new List<int>(col);
            return key;
        }


        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int col = key.Count;
            int row = cipherText.Length / col;
            int rem = cipherText.Length % col;
            string plainText = "";
            char[,] matrix = new char[row, col];
            int cnt = 0;

            // Rearrange columns based on key
            for (int c = 1; c <= key.Count; c++)
            {
                int pos = key.IndexOf(c);
                for (int r = 0; r < row; r++)
                {
                    if (cnt >= cipherText.Length) break;
                    matrix[r, pos] = cipherText[cnt];
                    cnt++;
                }
            }

            // Read out characters in correct order
            for (int rw = 0; rw < row; rw++)
            {
                for (int cl = 0; cl < col; cl++)
                {
                    plainText += matrix[rw, cl];
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.ToLower();

            int col = key.Count;
            int row = plainText.Length / col;
            int rem = plainText.Length % col;

            if (plainText.Length % col != 0)
            {
                row++;
                for (int i = 0; i < rem; i++)
                {
                    plainText += 'x';
                }
            }
            Console.WriteLine("row: " + row);
            string cipher = "";
            //char[,] matrix = new char[row,col];

            for (int i = 1; i < key.Count + 1; i++)
            {
                int pos = key.IndexOf(i);
                for (int j = 0; j < row; j++)
                {
                    cipher += plainText[pos];
                    pos += col;
                }
            }

            return cipher;
        }
    }
}
