using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int mod(int x, int m) { return (x % m + m) % m; }

        int[,] convert1DListTo2DArr(List<int> list1D, int m,int n)
        {
            int[,] arr2D = new int[m, n];
            for (int i = 0; i < m; i++)
                for (int j = 0; j < n; j++)
                    arr2D[i, j] = list1D[j * m + i];
            return arr2D;
        }
        List<int> convert2DArrTo1DList(int[,] arr2D,int m, int n)
        {
            List<int> list1D = new List<int>(new int[n*m]);
            for (int i = 0; i < m; i++)
                for (int j = 0; j < n; j++)
                    list1D[j * m + i] = arr2D[i, j];
            return list1D;
        }
        int[,] multiply2Matrices( int[,] plainText2d , int[,] key2d, int m, int n)
        {
            int[,] cipherText2d = new int[m, n];
            for (int i = 0; i < m; i++)
                for (int k = 0; k < n; k++)
                {
                    for (int j = 0; j < m; j++)
                        cipherText2d[i, k] += (key2d[i, j] * plainText2d[j, k]);
                    cipherText2d[i, k] %= 26;
                }
            return cipherText2d;
        }

        int getMultInvOfDet(int det)
        {
            int multInv = 1;
            // search for number b which{ b*det = 1 mod 26 && b<26 }
            for (; multInv < 26; multInv++)
                if (mod(multInv * det, 26) == 1) return multInv;
            if (multInv == 26)
                throw new InvalidAnlysisException();
            return multInv;
        }
        int[,] invert2x2Matrix(int[,] mtx)
        {
            int m = 2;
            int[,] invMtx = new int[2, 2];
            //a d
            invMtx[0, 0] = mod(mtx[1, 1], 26);
            invMtx[1, 1] = mod(mtx[0, 0], 26);
            //b c
            invMtx[0, 1] = mod(-1 * mtx[0, 1], 26);
            invMtx[1, 0] = mod(-1 * mtx[1, 0], 26);
            //find determinant
            int det = (mtx[0, 0] * mtx[1, 1]) - (mtx[0, 1] * mtx[1, 0]);
            det = mod(det, 26);
            //find multiplicative inverse of the determinant working modulo 26.
            int detMltInv = getMultInvOfDet(det);
            //multiply it with the cofactors
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    invMtx[i, j] = mod(invMtx[i, j] * detMltInv, 26);
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    mtx[i, j] = invMtx[i, j];
            return mtx;
        }
        int[,] invert3x3Matrix(int[,] mtx)
        {
            int m = 3;
            int[,] invMtx = new int[3, 3];
            //get cofactors
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int a = mtx[mod(i - 1, 3), mod(j - 1, 3)];
                    int b = mtx[mod(i - 1, 3), mod(j + 1, 3)];
                    int c = mtx[mod(i + 1, 3), mod(j - 1, 3)];
                    int d = mtx[mod(i + 1, 3), mod(j + 1, 3)];
                    invMtx[i, j] = a * d - b * c;
                    invMtx[i, j] *= (int)Math.Pow(-1, i + j);
                }
            }
            //find determinant
            int det = mtx[0, 0] * invMtx[0, 0] - mtx[0, 1] * invMtx[0, 1] + mtx[0, 2] * invMtx[0, 2];
            det = mod(det, 26);
            //find multiplicative inverse of the determinant working modulo 26.
            int MltInv = getMultInvOfDet(det);
            //multiply it with the cofactors
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    invMtx[i, j] = mod((int)Math.Pow(-1, i + j) * invMtx[i, j] * MltInv, 26);
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    mtx[i, j] = invMtx[j, i];
            return mtx;
        }
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
            int m = (int)Math.Sqrt(key.Count); //key matrix mxm
            //covert key to 2D list
            int[,] key2d = new int[m, m];
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    key2d[i, j] = key[i * m + j];
            //invert key matrix (check 2x2 or 3x3)
            if (m == 2)
                key2d = invert2x2Matrix(key2d);
            else
                key2d = invert3x3Matrix(key2d);
            int n = cipherText.Count / m; //number of columns in plain/cipher text 
            //covert plainText to 2D array
            int[,] cipherText2d = convert1DListTo2DArr(cipherText, m, n);
            //create 2D array for plainText & multiply2Matrices to decrypt
            int[,] plainText2d = multiply2Matrices(cipherText2d, key2d, m, n);
            //covert cipherText to 1D list & return
            return convert2DArrTo1DList(plainText2d, m, n);
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count); //key matrix mxm
            //covert key to 2D array
            int[,] key2d = new int[m, m];
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    key2d[i,j]=key[i * m + j];
            int n = plainText.Count / m; //number of columns in plain/cipher text 
            //covert plainText to 2D array
            int[,] plainText2d = convert1DListTo2DArr(plainText, m, n);
            //create 2D array for cipherText & multiply2Matrices to encrypt
            int[,] cipherText2d = multiply2Matrices(plainText2d,key2d,m,n);
            //covert cipherText to 1D list & return
            return convert2DArrTo1DList(cipherText2d, m, n); 
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
