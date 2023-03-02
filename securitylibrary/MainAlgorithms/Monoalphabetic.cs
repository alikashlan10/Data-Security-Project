using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            List<char> dist = new List<char>();
            for(int i = 0; i < 26; i++)
            {
                dist.Add((char)('a'+i));
            }
            char[] chars = new char[26];
            string key = "";
            for (int i = 0; i < cipherText.Length; i++) {
                int key_indx = (int)(plainText[i] - 'a');
                chars[key_indx] = cipherText[i];
                if(dist.Contains(cipherText[i]))
                    dist.Remove(cipherText[i]);
            }
            int j = 0;
            for (int i = 0; i < chars.Length; i++) {
                if (chars[i] != '\0')
                    key += chars[i];
                else
                {
                    key += dist[j];
                    j++;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            Dictionary<char, int> key_char_indx = new Dictionary<char, int>();
            for (int i = 0; i < key.Length; i++)
                key_char_indx[key[i]] = i;
            String plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
                plainText += (char)('a' + key_char_indx[cipherText[i]]);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            String cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
                cipherText += key[plainText[i]-'a'];
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
        }
    }
}