using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
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
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);
            int n = plainText.Count / m;
            List<int> cipherText = new List<int>(new int[plainText.Count]);

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    //k[i,j] = k[i*m+j]
                    for(int k = 0; k < n; k++)
                    {
                        //c[i,k] += k[i,j]*p[j,k]
                        cipherText[i*n + k] += key[i*m + j] * plainText[j*n + k];
                    }
                }
            }

            for (int i = 0; i < cipherText.Count; i++) 
                cipherText[i] %= 26;


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
