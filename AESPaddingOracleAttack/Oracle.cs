using System;
using System.Collections.Generic;

namespace AESPaddingOracleAttack
{
    class Oracle
    {
        private int blockSize = 16;
        private List<byte[]> blocks;

        public Oracle(byte[] encrypted, int blockSize = 16)
        {
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
