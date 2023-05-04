using System;
using System.Collections.Generic;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES algorithm = new DES();
            cipherText = algorithm.Decrypt(cipherText, key[0]);
            cipherText = algorithm.Encrypt(cipherText, key[1]);
            cipherText = algorithm.Decrypt(cipherText, key[0]);
            return cipherText;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES algorithm = new DES();
            plainText = algorithm.Encrypt(plainText, key[0]);
            plainText = algorithm.Decrypt(plainText, key[1]);
            plainText = algorithm.Encrypt(plainText, key[0]);
            return plainText;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}