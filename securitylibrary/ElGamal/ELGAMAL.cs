using System.Collections.Generic;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            long K = largepower(y, k, q);
            long C1 = largepower(alpha, k, q);
            long temp = K * m;
            long C2 = largepower(temp, 1, q);

            List<long> A = new List<long>();
            A.Add(C1);
            A.Add(C2);
            return A;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = largepower(c1, x, q);
            int Kinverse = mulinverse((int)K, q);
            long temp = c2 * Kinverse;
            int M = largepower(temp, 1, q);

            return M;

        }


        //bt7sb el mod lama ykon el rkm kber
        public int largepower(long M, int e, int n)
        {
            long result = 1;
            long baseValue = M % n;
            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    result = (result * baseValue) % n;
                }
                baseValue = (baseValue * baseValue) % n;
                e >>= 1;
            }
            return (int)result;
        }

        //bt7sb el multiplicative inverse 3shan ngeb el d fl decrypt
        public int mulinverse(int a, int m)
        {
            int m0 = m;
            int y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {

                int q = a / m;
                int t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }


    }
}

