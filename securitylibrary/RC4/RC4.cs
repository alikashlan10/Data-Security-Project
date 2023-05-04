using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool hexa = false;
            byte[] S = new byte[256];
            byte[] T = new byte[256];
            string check="";
            check += key[0];
            check += key[1];
            if (check=="0x")
            {
                hexa = true;
                key = hexaD(key);
                plainText = hexaD(plainText);
            }
            for (int i=0;i<256;i++)
            {
                S[i] = (byte)(i);
                T[i] = (byte)key[i % key.Length];
            }
           
            int j = 0;
            for (int i = 0; i< 256;i++)
            {
                j = (j + S[i] + T[i]) % 256;
                
                byte tempo = S[i];
                S[i] = S[j];
                S[j] = tempo;
            }
           
            int size = plainText.Length;
            int x = 0, y = 0;
            byte z, k;
            string cipher = "";
            for (int i=0;i<size;i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                byte tempoo = S[x];
                S[x] = S[y];
                S[y] = tempoo;
                z = (byte)((S[x] + S[y]) % 256);
                k = S[z];
                cipher += (char)(plainText[i]^k);
                
            }
            if (hexa == true)
            {
                return TextToHexa(cipher);
            }
            return cipher ;
        }
        private string hexaD(string hexadecimal)
        {
            hexadecimal = hexadecimal.Substring(2, hexadecimal.Length - 2);
            string strKey = "";
            for (int i = 0; i < hexadecimal.Length; i += 2)
            {
                Int64 intNum = Convert.ToInt64(hexadecimal.Substring(i, 2), 16);
                strKey += (char)intNum;
            }
            return strKey;
        }
        private string TextToHexa(string text)
        {
            string hexaText = "0x";
            for (int i =0;i<text.Length;i++)
            {
                Int64 intNum = (int)text[i];
                hexaText += intNum.ToString("X");
            }
            
            return hexaText;           
        }



    }
}
