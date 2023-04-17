using System;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        /*
            
            0 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            1 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
            2 B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
            3 04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
            4 09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
            5 53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
            6 D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
            7 51 A3 40 8F 92 9D,38,F5,BC B6 DA 21 10 FF F3 D2
            8 CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73
            9 60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB
            A E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79
            B E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08
            C BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A
            D 70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E
            E E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF
            F 8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16
         */
        public static string[,] sbox ={
                {"63","7C","77","7B","F2","6B","6F","C5","30","01","67","2B","FE","D7","AB","76"},
                {"CA","82","C9","7D","FA","59","47","F0","AD","D4","A2","AF","9C","A4","72","C0"},
                {"B7","FD","93","26","36","3F","F7","CC","34","A5","E5","F1","71","D8","31","15"},
                {"04","C7","23","C3","18","96","05","9A","07","12","80","E2","EB","27","B2","75"},
                {"09","83","2C","1A","1B","6E","5A","A0","52","3B","D6","B3","29","E3","2F","84"},
                {"53","D1","00","ED","20","FC","B1","5B","6A","CB","BE","39","4A","4C","58","CF"},
                {"D0","EF","AA","FB","43","4D","33","85","45","F9","02","7F","50","3C","9F","A8"},
                {"51","A3","40","7b","8F","92","9D","38","BC","B6","DA","21","10","FF","F3","D2"},
                {"CD","0C","13","EC","5F","97","44","17","C4","A7","7E","3D","64","5D","19","73"},
                {"60","81","4F","DC","22","2A","90","88","46","EE","B8","14","DE","5E","0B","DB"},
                {"E0","32","3A","0A","49","06","24","5C","C2","D3","AC","62","91","95","E4","79"},
                {"E7","C8","37","6D","8D","D5","4E","A9","6C","56","F4","EA","65","7A","AE","08"},
                {"BA","78","25","2E","1C","A6","B4","C6","E8","DD","74","1F","4B","BD","8B","8A"},
                {"70","3E","B5","66","48","03","F6","0E","61","35","57","B9","86","C1","1D","9E"},
                {"E1","F8","98","11","69","D9","8E","94","9B","1E","87","E9","CE","55","28","DF"},
                {"8C","A1","89","0D","BF","E6","42","68","41","99","2D","0F","B0","54","BB","16"}
        };
        public static int[,] M = {
                                    { 02, 03, 01, 01 },
                                    { 01, 02, 03, 01 },
                                    { 01, 01, 02, 03 },
                                    { 03, 01, 01, 02 }
                                    };

        static string missingZeros(string number, int len)
        {
            string tmp = "";
            for (int i = 0; i < len - number.Length; i++)
            {
                tmp += '0';
            }
            tmp += number;
            return tmp;
        }
        static string HexConverted(string strBinary)
        {
            strBinary = Convert.ToInt64(strBinary, 2).ToString("X");
            strBinary = missingZeros(strBinary, 2);
            //string strHex = "0x" + strBinary;
            return strBinary;
        }
        static string XOR(string x, string y)
        {
            string res = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i]) res += "0";
                else res += "1";
            }
            return res;
        }

        static string[,] subByte(string[,] s)
        {
            // The Byte Substitution Transformation: In AES, SBox......
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    int sRow;
                    if (s[row, col][0] >= '0' && s[row, col][0] <= '9')
                        sRow = s[row, col][0] - '0';
                    else
                        sRow = 10 + s[row, col][0] - 'A';

                    int sCol;
                    if (s[row, col][1] >= '0' && s[row, col][1] <= '9')
                        sCol = s[row, col][1] - '0';
                    else
                        sCol = 10 + s[row, col][1] - 'A';
                    string tmp = sbox[sRow, sCol];
                    s[row, col] = tmp;
                }
            }
            return s;
        }

        static string[,] shiftRow(string[,] s)
        {
            // The Shift Row Transformation:
            string[,] sShift = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    sShift[row, col] = s[row, (col + row) % 4];
                }
            }
            return sShift;
        }

        static string[,] matrixXOR(string[,] s, string[,] w)
        {
            // 's XOR w' ==> s(i, j) := s(i, j) ⊕ w(i, j) 
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    //hex to bin
                    //w
                    string tempW = Convert.ToString(Convert.ToInt64(w[row, col], 16), 2);//Convert Hex to Bin
                    tempW = missingZeros(tempW, 8);
                    //s
                    string tempS = Convert.ToString(Convert.ToInt64(s[row, col], 16), 2);//Convert Hex to Bin
                    tempS = missingZeros(tempS, 8);
                    //xor
                    string xor = XOR(tempW, tempS);
                    //bin to hex
                    xor = HexConverted(xor);
                    //update s
                    s[row, col] = xor;
                }
            }
            return s;
        }
        static string[,] convertToHexMatrix(string hexString)
        {
            string[,] hexMatrix = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    //adding 2 to the index to skip "0x";
                    hexMatrix[row, col] = hexString.Substring(2 + row * 2 + col * 8, 2);
                }
            }
            return hexMatrix;
        }

        int[,] multiply2Matrices(int[,] plainText2d, int[,] key2d, int m, int n)
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

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //FOR COMPARING TO THE PDF
            key = "0x00E9C9F2A509D4E8A8BBB760A02AAB08";

            //assign plainText to 4*4 Matrix
            string[,] s = convertToHexMatrix(plainText);
            //assign key to 4*4 Matrix
            string[,] w = convertToHexMatrix(key);
            // 's XOR w' ==> s(i, j) := s(i, j) ⊕ w(i, j) 
            s = matrixXOR(s, w);
            // The Byte Substitution Transformation: In AES, SBox......
            s = subByte(s);
            // The Shift Row Transformation:
            s = shiftRow(s);
            // The Mix Column Transformation:

            return plainText;
        }
    }
}




