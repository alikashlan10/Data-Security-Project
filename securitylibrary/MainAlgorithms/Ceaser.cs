using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        int mod(int x, int m){ return (x % m + m) % m; }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            String cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char equivalentLetter = (char)mod(plainText[i] - 'a' + key, 26);
                equivalentLetter += 'a';
                cipherText += equivalentLetter;

            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, key * -1);
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = mod(cipherText[0] - plainText[0], 26);
            return key;
        }
    }
}