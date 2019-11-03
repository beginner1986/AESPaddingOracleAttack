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
