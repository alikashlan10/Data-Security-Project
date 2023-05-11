using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> Key = new List<int>();
            int K1, K2;

            int Ya = ModPower(alpha, xa, q);
            int Yb = ModPower(alpha, xb, q);
            K1 = ModPower(Ya, xb, q);
            Key.Add(K1);
            K2 = ModPower(Yb, xa, q);
            Key.Add(K2);
            return Key;
        }

        //bgm3 mod
        public static int Mod(int a, int b, int mod)
        {

            int r = (a * b) % mod;
            int x;
            if (r < 0)
            {
                x = r + mod;
            }
            else
            {
                x = r;
            }
            return x;
        }

        //b3ml divide le large power
        public static int ModPower(int Base, int power, int mod)
        {
            int result = 1;

            while (power > 0)
            {
                if (power % 2 == 1)
                {
                    result = Mod(result, Base, mod);
                }

                Base = Mod(Base, Base, mod);
                power /= 2;
            }

            return result;
        }
    }
}
