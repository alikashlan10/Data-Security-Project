namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// Find the multiplicative inverse of number mod baseN using the Extended Euclid algorithm
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Multiplicative inverse, -1 if no inverse</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //m baseN  number b
            int a1 = 1, a2 = 0, a3 = baseN;
            int b1 = 0, b2 = 1, b3 = number;
            int q, t1, t2, t3;

            while (b3 != 0 && b3 != 1)
            {
                q = a3 / b3;
                t1 = a1 - q * b1;
                t2 = a2 - q * b2;
                t3 = a3 - q * b3;
                a1 = b1;
                a2 = b2;
                a3 = b3;
                b1 = t1;
                b2 = t2;
                b3 = t3;
            }

            // no inverse
            if (b3 == 0)
            {
                return -1;
            }
            // inverse is b2
            else
            {
                //  b2 to +ve
                if (b2 < 0)
                {
                    b2 += baseN;
                }
                return b2;
            }

        }
    }
}
