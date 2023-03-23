using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        int mod(int x, int m) { return (x % m + m) % m; }
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string keystream = "";
            for (int i = 0; i < cipherText.Length; i++)
                keystream += (char)('a' + mod((cipherText[i] - plainText[i]), 26));
            string key = plainText.Substring(0, 6);
            for (int i = 3; i < keystream.Length; i++)
            {
                if (key == keystream.Substring(i, 6))
                {
                    keystream = keystream.Remove(i);
                }

            }

            return keystream;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                char tmp = (char)('a' + mod((cipherText[i] - key[i]), 26));
                plainText += tmp;
                key += tmp;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            key += plainText;
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
                cipherText += (char)('a' + ((plainText[i] - 'a' + key[i] - 'a') % 26));
            return cipherText;
        }
    }
}