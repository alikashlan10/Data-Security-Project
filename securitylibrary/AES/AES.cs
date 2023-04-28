using System;
using System.Collections.Generic;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] inverseSBox = new string[16, 16] {
    {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
    {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
    {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
    {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
    {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
    {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
    {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
    {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
    {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
    {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
    {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
    {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
    {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
    {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
    {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
    {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
};
        static void generateKeys(string[,] w, List<string[,]> keys)
        {
            keys.Add(w);
            for (int i = 1; i <= 10; i++)
            {
                string[,] oldKey = keys[i - 1];
                string[,] newKey = new string[4, 4];
                string[] k = new string[4];
                for (int j = 0; j < 4; j++)
                    k[j] = oldKey[(j + 1) % 4, 3];
                //sBox
                int x = 0;
                for (int j = 0; j < 4; j++)
                {
                    int sRow;
                    if (k[j][0] >= '0' && k[j][0] <= '9')
                        sRow = k[j][0] - '0';
                    else
                        sRow = 10 + k[j][0] - 'A';

                    int sCol;
                    if (k[j][1] >= '0' && k[j][1] <= '9')
                        sCol = k[j][1] - '0';
                    else
                        sCol = 10 + k[j][1] - 'A';
                    string tmp = sBox[sRow, sCol];
                    k[j] = tmp;
                }


                k[0] = HexXOR(k[0], Rcon[i - 1]);
                for (int j = 0; j < 4; j++)
                {
                    newKey[j, 0] = HexXOR(k[j], oldKey[j, 0]);
                }
                for (int col = 1; col < 4; col++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        newKey[j, col] = HexXOR(oldKey[j, col], newKey[j, col - 1]);
                    }
                }
                keys.Add(newKey);
            }
        }
        public static string[] Rcon = { "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36" };
        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string[,] s = convertToHexMatrix(cipherText);
            string[,] w = convertToHexMatrix(key);
            List<string[,]> keys = new List<string[,]>();
            generateKeys(w, keys);
            s = AddRoundKey(s, keys[10]);

            for (int i = 9; i <= 1; i++)
            {
                s = invShiftRow(s);
                s = invSubByte(s);
                s = mixColumn(s);//inv
                s = AddRoundKey(s, keys[i]);
            }
            s = invShiftRow(s);
            s = invSubByte(s);
            s = AddRoundKey(s, keys[0]);

            string plainText = convertToHexString(s);
            return plainText;
        }
        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            //FOR COMPARING TO THE PDF
            //key = "0x00E9C9F2A509D4E8A8BBB760A02AAB08";
            string[,] s = convertToHexMatrix(plainText);
            string[,] w = convertToHexMatrix(key);
            List<string[,]> keys = new List<string[,]>();
            generateKeys(w, keys);
            s = AddRoundKey(s, keys[0]);
            for (int i = 1; i <= 9; i++)
            {
                s = subByte(s);
                s = shiftRow(s);
                s = mixColumn(s);
                s = AddRoundKey(s, keys[i]);
            }
            s = subByte(s);
            s = shiftRow(s);
            s = AddRoundKey(s, keys[10]);
            string cipherText = convertToHexString(s);
            return cipherText;
        }
        static string convertToHexString(string[,] hexMatrix)
        {
            string hexString = "0x";
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    //adding 2 to the index to skip "0x";
                    hexString += hexMatrix[row, col];
                }
            }
            return hexString;
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
        static string[,] AddRoundKey(string[,] s, string[,] w)
        {
            //s_dash(i, j) := s(i, j) ⊕ w(i, j) 
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    s[row, col] = HexXOR(w[row, col], s[row, col]);
                }
            }
            return s;
        }
        static string ConvertHextoBin(string hexString)
        {
            Int64 intNum = Convert.ToInt64(hexString, 16);
            string binString = Convert.ToString(intNum, 2);
            binString = missingZeros(binString, 8);
            return binString;
        }
        static string HexXOR(string x, string y)
        {
            x = ConvertHextoBin(x);
            y = ConvertHextoBin(y);
            string res = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i]) res += "0";
                else res += "1";
            }
            res = HexConverted(res);
            return res;
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
        public static string[,] sBox = new string[16, 16]{
       // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
        {"63","7C","77","7B","F2","6B","6F","C5","30","01","67","2B","FE","D7","AB","76"},//0
        {"CA","82","C9","7D","FA","59","47","F0","AD","D4","A2","AF","9C","A4","72","C0"},//1
        {"B7","FD","93","26","36","3F","F7","CC","34","A5","E5","F1","71","D8","31","15"},//2
        {"04","C7","23","C3","18","96","05","9A","07","12","80","E2","EB","27","B2","75"},//3
        {"09","83","2C","1A","1B","6E","5A","A0","52","3B","D6","B3","29","E3","2F","84"},//4
        {"53","D1","00","ED","20","FC","B1","5B","6A","CB","BE","39","4A","4C","58","CF"},//5
        {"D0","EF","AA","FB","43","4D","33","85","45","F9","02","7F","50","3C","9F","A8"},//6
        {"51","A3","40","8F","92","9D","38","F5","BC","B6","DA","21","10","FF","F3","D2"},//7
        {"CD","0C","13","EC","5F","97","44","17","C4","A7","7E","3D","64","5D","19","73"},//8
        {"60","81","4F","DC","22","2A","90","88","46","EE","B8","14","DE","5E","0B","DB"},//9
        {"E0","32","3A","0A","49","06","24","5C","C2","D3","AC","62","91","95","E4","79"},//10
        {"E7","C8","37","6D","8D","D5","4E","A9","6C","56","F4","EA","65","7A","AE","08"},//11
        {"BA","78","25","2E","1C","A6","B4","C6","E8","DD","74","1F","4B","BD","8B","8A"},//12
        {"70","3E","B5","66","48","03","F6","0E","61","35","57","B9","86","C1","1D","9E"},//13
        {"E1","F8","98","11","69","D9","8E","94","9B","1E","87","E9","CE","55","28","DF"},//14
        {"8C","A1","89","0D","BF","E6","42","68","41","99","2D","0F","B0","54","BB","16"} //15
        };
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
                    string tmp = sBox[sRow, sCol];
                    s[row, col] = tmp;
                }
            }
            return s;
        }
        static string[,] invSubByte(string[,] s)
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
                    string tmp = inverseSBox[sRow, sCol];
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
        static string[,] invShiftRow(string[,] s)
        {
            // The Shift Row Transformation:
            string[,] sShift = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    sShift[row, col] = s[row, (col - row + 4) % 4];
                }
            }
            return sShift;
        }
        public static int[,] M = {
                                    { 2, 3, 1, 1 },
                                    { 1, 2, 3, 1 },
                                    { 1, 1, 2, 3 },
                                    { 3, 1, 1, 2 }
                                 };
        string[,] mixColumn(string[,] s)
        {
            string x1B = "00011011";
            string[,] s_dash = new string[4, 4];
            for (int row = 0; row < 4; row++)
                for (int col = 0; col < 4; col++)
                    s[row, col] = ConvertHextoBin(s[row, col]);

            for (int i = 0; i < 4; i++)
            {
                for (int k = 0; k < 4; k++)
                {
                    s_dash[i, k] = "00000000";
                    for (int j = 0; j < 4; j++)
                    {
                        string tmp = s[j, k];
                        if (M[i, j] >= 2)
                        {
                            tmp = shiftLeft(tmp);
                            if (s[j, k][0] == '1')
                                tmp = XOR(tmp, x1B);
                        }
                        if (M[i, j] == 3)
                            tmp = XOR(s[j, k], tmp);
                        s_dash[i, k] = XOR(s_dash[i, k], tmp);
                    }
                }
            }
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    s_dash[row, col] = HexConverted(s_dash[row, col]);
                }
            }
            return s_dash;
        }


        static string shiftLeft(string binaryNumber)
        {
            string shiftedBinaryNumber = binaryNumber.Substring(1, binaryNumber.Length - 1);
            shiftedBinaryNumber += 0;
            return shiftedBinaryNumber;
        }


    }
}





