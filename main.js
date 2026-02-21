import fs from 'fs';
import crypto from 'crypto'
import path from 'path';
import NodeID3 from 'node-id3';
const args = process.argv.slice(2);
function aes128EcbDecrypt(encrypted,secretKey) {
    try {
        // 1. 将十六进制密钥转换为 Buffer (这正是你之前学习的 Buffer 转换)
        const keyBuffer = Buffer.from(secretKey);
        
        // 验证密钥长度：AES-128 需要 16 字节
        if (keyBuffer.length !== 16) {
            throw new Error('密钥长度必须为16字节（32位十六进制字符）');
        }

        // 2. 将Base64密文转换为 Buffer
        const encryptedBuffer = encrypted;

        // 3. 创建解密器
        //    - 'aes-128-ecb': 指定算法为AES-128，模式为ECB
        //    - null: ECB模式不需要初始化向量(IV)[citation:5]
        const decipher = crypto.createDecipheriv('aes-128-ecb', keyBuffer, null);
        
        // 4. 设置自动填充（默认就是true，PKCS5Padding/PKCS7Padding会自动处理）[citation:1][citation:3]
        //    Node.js的crypto模块默认使用PKCS#7填充，它与PKCS#5在AES下完全兼容[citation:2]
        decipher.setAutoPadding(true);

        // 5. 执行解密
        //    - 第一块：update 返回解密后的部分数据（可能不完整）
        //    - 参数含义：输入数据, 输入编码, 输出编码
        const decryptedParts = [
            decipher.update(encryptedBuffer)
        ];
        
        // final可能还有数据
        const finalPart = decipher.final();
        if (finalPart.length > 0) {
            decryptedParts.push(finalPart);
        }

        // 5. 合并所有部分并返回Buffer
        return Buffer.concat(decryptedParts);
        
    } catch (error) {
        console.error('解密失败:', error.message);
        throw error;
    }
}
class CR4{
    #box
    constructor(){
        this.box = new Array(256)
    }
    /**
     * CR4-KSA秘钥调度算法
     * 功能:生成s-box
     *
     * @param key 密钥
     */
     KSA(key) {
        var len = key.length;
        for (var i = 0; i < 256; i++) {
            this.box[i] = i;
        }
        for (var i = 0, j = 0; i < 256; i++) {
            j = (j + this.box[i] + key[i % len]) & 0xff;
            var swap = this.box[i];
            this.box[i] = this.box[j];
            this.box[j] = swap;
        }
    }
    
    /**
     * CR4-PRGA伪随机数生成算法
     * 功能:加密或解密
     *
     * @param data   加密|解密的数据
     * @param length 数据长度
     */
    PRGA(data,length) {
        for (var k = 0, i, j; k < length; k++) {
            i = (k + 1) & 0xff;
            j = (this.box[i] + i) & 0xff;
            data[k] ^= this.box[(this.box[i] + this.box[j]) & 0xff];
        }
        return data;
    }
}

class Ncm{
    #filenumber = 0;
    constructor(filename,output){
        this.filenumber = 0;
        this.filename = filename;
        this.output = output;
    }
    async isNcm(filename){
        let test = await fs.promises.open(filename,"r");
        let head = Buffer.alloc(10);
        let ncmHead = Buffer.from([0x43,0x54,0x45,0x4e,0x46,0x44,0x41,0x4d,0x01,0x70]);
        await test.read(head,0,10,0);
        if(head.compare(ncmHead)){
            return false;
        }
        this.filenumber += 10;
        return true;
    }
    async cr4Key(filename){
        let test = await fs.promises.open(filename,"r");
        let length = Buffer.alloc(4);
        await test.read(length,0,4,10);
        this.filenumber += 4 ;
        let keyBytes = Buffer.alloc(length.readUInt32LE(0))
        await test.read(keyBytes,0,length.readUInt32LE(0),this.filenumber);
        this.filenumber += length.readUInt32LE(0);
         //1.按字节对0x64异或
            for (var i = 0; i < length.readUInt32LE(0); i++) {
                keyBytes[i] ^= 0x64;
            }
        let dekey = aes128EcbDecrypt(keyBytes,[0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57]);
        let key = Buffer.alloc(dekey.length-17);
        dekey.copy(key,0,17,dekey.length)
        return key;
    }
    async metaData(filename) {
        let test = await fs.promises.open(filename,"r");
        let length = Buffer.alloc(4);
        await test.read(length,0,4,142);
        this.filenumber += 4 ;
        let keyBytes = Buffer.alloc(length.readUInt32LE(0));
        await test.read(keyBytes,0,length.readUInt32LE(0),this.filenumber);
        this.filenumber += length.readUInt32LE(0) + 9;
        for (var i = 0; i < length.readUInt32LE(0); i++) {
                keyBytes[i] ^= 0x63;
            }
        let info = Buffer.alloc(keyBytes.length-22);
        keyBytes.copy(info,0,22,keyBytes.length)
        let key = Buffer.from(info.toString(),'base64');
        let dekey = aes128EcbDecrypt(key,[0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28]);
        let metaInfo = Buffer.alloc(dekey.length-6);
        dekey.copy(metaInfo,0,6,dekey.length);
        return metaInfo.toString();
    }
    async imgData(filename) {//jpg格式
        let test = await fs.promises.open(filename,"r");
        let length = Buffer.alloc(4);
        console.log(this.filenumber)
        await test.read(length,0,4,this.filenumber);
        this.filenumber += 4 ;
        let keyBytes = Buffer.alloc(length.readUInt32LE(0));
        await test.read(keyBytes,0,length.readUInt32LE(0),this.filenumber);
        this.filenumber += length.readUInt32LE(0);
        test.close();
        return keyBytes;
    }
    async musicData(filename,key){
        const cr4 = new CR4();
        cr4.KSA(key);
        var fileBuffer = fs.readFileSync(filename);
        var buffer = Buffer.alloc(fileBuffer.length-this.filenumber);
        fileBuffer.copy(buffer,0,this.filenumber,fileBuffer.length);
        buffer = cr4.PRGA(buffer,fileBuffer.length-this.filenumber)
        return buffer
    }
    async turnUp(){
        await this.isNcm(this.filename);
        var key = await this.cr4Key(this.filename);
        var meta = JSON.parse((await this.metaData(this.filename)).toString());
        var img = await this.imgData(this.filename);
        meta.image = {
            mime: "image/jpeg",
            type: 3,
            description: "封面",
            imageBuffer:img
        }
        var metaInfo = {
            title:meta.musicName,
            artist:meta.artist[0][0],
            album:meta.album,
            image:meta.image
        }
        let data = await this.musicData(this.filename,key);
        const outputFile = NodeID3.write(metaInfo,data)
        let output = await fs.promises.open(this.output + meta.musicName+'-'+meta.artist[0][0]+'.mp3',"w");
        
        console.log(meta)
        output.write(outputFile);
        output.close();
    }
}
const help = `
Ncm2Mp3 
Version:v0.2
Author: BrianLing

Usage:
    node main.js [arg1]
        arg1:
            -h :
                帮助文档

            -c [filepath]:
                转换filepath的文件至源文件夹
                
            -d [source_folder_path] [destnation_folder_path]:
                 转换源文件夹中所有ncm文件至目标文件夹
            `;
switch(args[0]){
    case '-h':
        console.log(help);
            break;
    case '-c':
        console.log(args[1]);
        // 定义文件路径
        const filePath = args[1];
        // 获取文件所在文件夹路径
        const directoryPath = path.dirname(filePath);
        // 确保路径以斜杠结尾（匹配你示例中的C:/test/格式）
        const dirWithSlash = path.join(directoryPath, '/');
            
        const ncm = new Ncm(args[1],dirWithSlash);
        ncm.turnUp();
        break;
    case '-d':
        let dir = fs.readdirSync(path.join(args[1],'/')).filter(file => 
            path.extname(file).toLowerCase() === '.ncm'
        );
        dir.forEach(file => {
            const ncm = new Ncm(path.join(args[1],'/')+file,path.join(args[2],'/'));
            ncm.turnUp();
        });
        break;
    default:
        console.log(help);
            break;
}
