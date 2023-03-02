using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        int mod(int x, int m)
        {
            return (x % m + m) % m;
        }

        public string Encrypt(string plainText, int key)
        {

            String ct = "";
            char temp;


            for (int i = 0; i < plainText.Length; i++)
            {
                temp = (char)mod(plainText[i] + key - 'a', 26);
                temp += 'a';
                ct += temp;

            }

            return ct;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            return Encrypt(cipherText, key * -1);
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = (int)mod(cipherText[0] - plainText[0], 26);
            return key;
        }
    }
}