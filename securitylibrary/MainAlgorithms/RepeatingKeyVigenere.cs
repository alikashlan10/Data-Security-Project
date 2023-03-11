using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        int mod(int x, int m){ return (x % m + m) % m; }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            while (key.Length < cipherText.Length)
                key += key;
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
                plainText += (char)( 'a' + mod((cipherText[i] - key[i] ) , 26));
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            while (key.Length < plainText.Length)
                key += key;
            string cipherText="";
            for(int i = 0; i < plainText.Length; i++)
                cipherText += (char)('a'+(( plainText[i]-'a' + key[i]-'a' )% 26));
            return cipherText;
        }
    }
}