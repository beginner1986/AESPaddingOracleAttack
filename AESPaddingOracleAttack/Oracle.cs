using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESPaddingOracleAttack
{
    class Oracle
    {
        private int blockSize = 16;
        private List<byte[]> blocks;


        // function delegate to check padding correctness
        public delegate bool CheckPadding(byte[] encrypted);
        private CheckPadding isCorrect;

        public Oracle(CheckPadding isCorrect, byte[] encrypted, int blockSize = 16)
        {
            this.isCorrect = isCorrect;
            this.blockSize = blockSize;
            blocks = getBlocks(encrypted);

            // DEBUG: check if bytes are read correctly
            // Console.WriteLine(System.Text.Encoding.UTF8.GetString(ListToArray(blocks)));
        }

        public byte[] Decrypt()
        {
            // list for decrypted bytes
            List<byte[]> result = new List<byte[]>();

            // iterate all the blocks
            for(int i=0; i<blocks.Count; i++)
            {
                // check if it is the last decodable block
                if (i + 1 == blocks.Count)
                    break;

                // decrypt a single data block
                byte[] temp = DecryptBlock(blocks[i], blocks[i + 1]);
                result.Add(temp);
            }

            /*
            // DEBUG: check if list is properly generated
            foreach(byte[] block in result)
            {
                Console.Write(System.Text.Encoding.UTF8.GetString(block));
            }
            */

            // return dcrypted byte array
            return ListToArray(result);
        }

        private byte[] DecryptBlock(byte[] previous, byte[] next)
        {
            // array with single decrypted block
            byte[] result = new byte[blockSize];

            // test every possible padding value <1; blockSize>
            // if last block is full size, then one more block with value 16 paddings will be added
            for(int padding=1; padding<=blockSize; padding++)
            {
                byte[] garbage = new byte[blockSize];

                if(result[blockSize - 1] != 0)
                {
                    for(int i=0; i<blockSize; i++)
                    {
                        if (result[i] == 0)
                            continue;

                        garbage[i] = (byte)(padding ^ result[i] ^ previous[i]);
                    }
                }

                // create double-sized block consisting of generated garbage block and real next block
                byte[] doubleBlock = new byte[2 * blockSize];
                Array.Copy(garbage, doubleBlock, blockSize);
                Array.Copy(next, 0, doubleBlock, blockSize, blockSize);

                // coorect byte value found
                int correctByte = -1;

                // check all the possibilities to get correct padding value
                for(int i=0; i<255; i++)
                {
                    doubleBlock[doubleBlock.Length - padding - blockSize] = (byte)i;
                    if(isCorrect(doubleBlock))
                    {
                        correctByte = i;
                        break;
                    }
                }

                // calculate real value of decrypted byte
                int decrypted = (padding ^ previous[blockSize - padding] ^ correctByte);
                //add decrypted byte to the result array
                result[blockSize - padding] = (byte)decrypted;
            }

            // check if decrypted value contains some padding
            int length = blockSize - result[blockSize - 1];
            if(length > 0)
            {
                // if it contains return pure data with no padding
                byte[] pureData = new byte[length];
                Array.Copy(result, pureData, length);

                return pureData;
            }

            // else return complete decrypted block
            return result;
        }

        private byte[] ListToArray(List<byte[]> list)
        {
            // result byte array with final size
            byte[] result = new byte[0];

            for(int i=0; i<list.Count; i++)
            {
                byte[] block = list[i];
                byte[] temp = new byte[result.Length];
                Array.Copy(result, temp, result.Length);
                result = new byte[temp.Length + block.Length];
                Array.Copy(temp, result, temp.Length);
                Array.Copy(block, 0, result, temp.Length, block.Length);
            }

            // return list as byte array
            return result;
        }

        private List<byte[]> getBlocks(byte[] encrypted)
        {
            // list of bloc-sized byte arrays - by default 16
            List<byte[]> result = new List<byte[]>();

            for(int i=0; i<encrypted.Length; i += blockSize)
            {
                // array to store currnet block
                byte[] temp = new byte[blockSize];
                // copy current block to temporary variable
                Array.Copy(encrypted, i, temp, 0, blockSize);
                // add read block to the result list
                result.Add(temp);
            }

            // return list of blocks
            return result;
        }
    }
}
