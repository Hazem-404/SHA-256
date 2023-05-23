using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SHA256Alog
{
    class Message
    {
        public String OriginalMessage;
        public String EncryptedMessage;
    
        Int64 [] BlocksTemp = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        Int64[] WordTemp = { 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        List<List<int>> Word = new List<List<int>>();
        List<List<int>> Blocks = new List<List<int>>();
        List<List<int>> HashValues = new List<List<int>>();
        public Message(String OriginalMessage)
        {
            this.OriginalMessage = OriginalMessage;
            Encrypt();
        }
        public void PrintEncryptedMessage()
        {
            Console.WriteLine(EncryptedMessage);
        }
        private void UpdateHashValues()
        {
            for(int i=0;i<8;i++)
            {
                HashValues[i] = Add(new List<int>(HashValues[i]), new List<int>(Blocks[i]));
            }
            for(int i=0;i<8;i++)
                for(int j=0;j<32;j+=4)
                {
                    int shift = 3;
                    int num = 0;
                    for(int k=j;k<j+4;k++)
                    {
                        if (HashValues[i][k] == 1)
                            num += (1 << shift);
                        shift--;
                    }
                    char temp;
                    if(num<10)
                    {
                        num += 48;
                        temp =(char)num;
                    }else
                    {
                        num -= 10;
                        temp= (char)(num + 'A');
                    }
                    EncryptedMessage += temp;


                }

        }
        private List<int> Add(List<int>Operand1, List<int>Operand2)
        {
            List<int> Value=new List<int>();
            int cur = 0;
            for(int i=31;i>=0;i--)
            {
                cur += Operand1[i] + Operand2[i];
                Value.Add(cur % 2);
                cur /= 2;
            }
            Value.Reverse();
            return Value;
        }
        private List<int> RotateRight(List<int>Value, int cnt)
        {
            List<int> Result = new List<int>();
            for (int i = 32-cnt, j = 0; j < 32; j++, i = (i + 1) % 32)
                Result.Add(Value[i]);
            return Result;

        }
        private List<int> Invert(List<int> Value)
        {
            for (int i = 0; i < 32; i++)
                Value[i] = 1 - Value[i];
            return Value;
        }
        private List<int>XOR(List<int>Operand1, List<int> Operand2)
        {
            List<int> Result = new List<int>();
            for (int i = 0; i < 32; i++)
                Result.Add((Operand1[i] ^ Operand2[i]));
            return Result;
        }
        private List<int> AND(List<int> Operand1, List<int> Operand2)
        {
            List<int> Result = new List<int>();
            for (int i = 0; i < 32; i++)
                Result.Add((Operand1[i] & Operand2[i]));
            return Result;
        }

        private List<int>RightShift(List<int>Operand,int cnt)
        {
            List<int> Result = new List<int>();
            for(int i=0;i<cnt;i++)
                Result.Add(0);

            for (int i=0;i<32&&Result.Count<32;i++)
            {
                Result.Add(Operand[i]);
            }
            return Result;
        }
        private List<int> Sigma0Σ(List<int>Value)
        {
            return XOR(XOR(RotateRight(Value, 2) , RotateRight(Value, 13)), RotateRight(Value, 22));
        }
        private List<int> Sigma1Σ(List<int>Value)
        {
            return XOR(XOR(RotateRight(Value, 6) , RotateRight(Value, 11)), RotateRight(Value, 25));
        }
        private List<int> Sigma0σ(List<int> Value)
        {
            return XOR(XOR(RotateRight(Value, 7),RotateRight(Value, 18)),RightShift(Value,3));
        }
        private List<int> Sigma1σ(List<int> Value)
        {
            return XOR(XOR(RotateRight(Value, 17), RotateRight(Value, 19)), RightShift(Value, 10));
        }
        private List<List<int>> InitalizeW(List<List<int>> W)
        {
            for (int i = 16; i < 64; i++)
                W[i] = Add(Add(W[i - 16], Sigma0σ(W[i - 15])), Add(W[i - 7], Sigma1σ(W[i - 2])));
            return W;
        }
        private void UpdateBlocks(List<List<int>> W)
        {

            for (int i = 0; i < 64; i++)
            {
                List<int> Choice = XOR(AND(new List<int>(Blocks[4]), new List<int>(Blocks[5])), AND(Invert(new List<int>(Blocks[4])), new List<int>(Blocks[6])));
                List<int> Majority = XOR(XOR(AND(new List<int>(Blocks[0]), new List<int>(Blocks[1])), AND(new List<int>(Blocks[0]), new List<int>(Blocks[2]))), AND(new List<int>(Blocks[1]), new List<int>(Blocks[2])));
                List<int> temp1 = Add(Add(Add(new List<int>(Blocks[7]), Sigma1Σ(new List<int>(Blocks[4]))), Add(new List<int>(Word[i]), new List<int>(W[i]))), new List<int>(Choice));
                List<int> temp2 = Add(Sigma0Σ(new List<int>(Blocks[0])), new List<int>(Majority));
                Blocks[7] = new List<int>(new List<int>(Blocks[6]));
                Blocks[6] = new List<int>(new List<int>(Blocks[5]));
                Blocks[5] = new List<int>(new List<int>(Blocks[4]));
                Blocks[4] = new List<int>(Add(new List<int>(Blocks[3]) , new List<int>(temp1)));
                Blocks[3] = new List<int>(new List<int>(Blocks[2]));
                Blocks[2] = new List<int>(new List<int>(Blocks[1]));
                Blocks[1] = new List<int>(new List<int>(Blocks[0]));
                Blocks[0] = new List<int>(Add(new List<int>(temp1) , new List<int>(temp2)));
            }
        }
        private void initalizeWandBlocks()
        {
            for(int i=0;i<64;i++)
            {
                List<int> Value = DecimalToBinary(WordTemp[i],32);
                Word.Add(Value);
            }
            for(int i=0;i<8;i++)
            {
                List<int> Value = DecimalToBinary(BlocksTemp[i], 32);
                Blocks.Add(Value);
                HashValues.Add(Value);
            }
        }
        private List<int> DecimalToBinary(Int64 DecimalValue,int size)
        {
            List<int> BinaryRepresentation = new List<int>();
            while (DecimalValue > 0)
            {
                if (DecimalValue % 2 == 1)
                    BinaryRepresentation.Add(1);
                else BinaryRepresentation.Add(0);
                DecimalValue /= 2;
            }
            while (BinaryRepresentation.Count < size)
            {
                BinaryRepresentation.Add(0);
            }
            BinaryRepresentation.Reverse();
            return BinaryRepresentation;
        }
        private void Encrypt()
        {
            initalizeWandBlocks();
            List<int> Numbers=new List<int> ();
            for(int i=0;i<OriginalMessage.Length;i++)
            {
                int DecimalValue =(int)OriginalMessage[i];
                List<int> BinaryRepresentation = DecimalToBinary(DecimalValue,8);
                for (int j = 0; j < 8; j++)
                    Numbers.Add(BinaryRepresentation[j]);
            }
            Numbers.Add(1);
            while(Numbers.Count%512!=448)
            {
                Numbers.Add(0);
            }
            int size = 8 * OriginalMessage.Length;
            List<int> BinaryRepresentationOfSize= DecimalToBinary(size,64);
            for (int i = 0; i < 64; i++)
                Numbers.Add(BinaryRepresentationOfSize[i]);
            for (int i = 0; i < Numbers.Count; i += 512)
            {
                List<List<int>> W = new List<List<int>>();
                for (int j = i; j < i + 512; j += 32)
                {
                   List<int> N = new List<int>();
                    for (int k = j; k < j + 32; k++)
                    {
                        N.Add(Numbers[k]);
                    }
                    W.Add(N);
                }
                List<int> Num = new List<int>();
                for (int k = 0; k < 32; k++)
                    Num.Add(0);
                while (W.Count < 64)
                    W.Add(Num);
                W = InitalizeW(W);
                UpdateBlocks(W);
            }
            UpdateHashValues();
        }
    }
}
