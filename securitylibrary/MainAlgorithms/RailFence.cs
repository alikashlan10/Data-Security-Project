using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = -1;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == cipherText[1])
                {
                    key = i;
                    if (plainText[2 * key] == cipherText[2])
                    {
                        return key;
                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int length = cipherText.Length;
            int k = length % key;
            int depth = (length / key);
            if (k != 0)
            {
                depth += 1;
            }

            char[,] arr = new char[key, depth];
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if ((j * depth) + i < cipherText.Length)
                        arr[j, i] = cipherText[(j * depth) + i];

                }
            }
            string encrypted = "";
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    encrypted += arr[j, i];

                }
            }
            return encrypted;

        }

        public string Encrypt(string plainText, int key)
        {
            int length = plainText.Length;
            int k = length % key;
            int depth = (length / key);
            if (k != 0)
            {
                depth += 1;
            }

            char[,] arr = new char[depth, key];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    if ((j * key) + i < plainText.Length)
                        arr[j, i] = plainText[(j * key) + i];

                }
            }
            string encrypted = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    encrypted += arr[j, i];

                }
            }
            return encrypted;
        }
    }




}