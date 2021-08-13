Imports System.IO
Imports System.IO.Compression
Imports System.Net
Imports System.Runtime.CompilerServices
Imports System.Runtime.InteropServices
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.RegularExpressions
Imports System.Threading
Imports DevComponents.DotNetBar
Imports James_reborns_Protection_Program.algorithmslist
Imports Microsoft.VisualBasic.CompilerServices
Public Class JamesrebornsProtections
#Region "TAB NAMES INFO?"
#Region "FileCryption Hide shit"
#Region "File TAB"
    'Tabitem6 = File Tab All Things
    'Tabitem29 = File Encryption
    'Tabitem30 = File Decryption Method
    'Tabitem33 = File Encryption Method
#End Region
#Region "Entrypoint"
    'Tabitem7 = Entry Point Tab All Things
    'Tabitem2 = Simple Entry Point
    'Tabitem14 = Custom Simple Entry Point
    'Tabitem8 = Crypted Entry Point
#End Region
    'Tabitem5 = File Cryption (Full Tab)
#End Region
#Region "Text Cryption Hide shit"
    'Tabitem10 = Main Page
#Region "Gens"
    'Tabitem15 = Gens Full Tab
    'Tabitem20 = P1
    'Tabitem24 = P2
    'Tabitem28 = P3
    'Tabitem31 = P4
    'Tabitem34 = P5
    'Tabitem35 = P6
#End Region
#Region "Advanced Text Cryption"
    'Tabitem32 = Advanced Text Cryption Full Tab
    'Tabitem16 = Normal Methods
    'Tabitem17 = Secret Key Methods
#End Region
#Region "Random Pool"
    'Tabitem38 = Random Pool Full Tab
    'Tabitem39 = Pool
#Region "Pool Settings"
    'Tabitem41 = Pool Settings
    'Tabitem42 = P1
    'Tabitem43 = Range Methods
    'Tabitem44 = Matrix Methods
#Region "Mouse Methods"
    'Tabitem55 = Mouse Methods Full Tab
    'Tabitem56 = Mouse Hover
    'Tabitem57 = Mouse Click
#End Region
#End Region
#End Region
#Region "Pastebin"
    'Tabitem58 = Pastebin Full Tab
    'Tabitem62 = Login
    'Tabitem59 = Create Paste
    'Tabitem60 = Information?
#End Region
#End Region
#Region "Methods / Gen Settings"
    'Tabitem19 = Methods / Gen Settings Full Tab
#Region "Settings"
    'Tabitem3 = Settings Full Tab
#Region "Gen Settings"
    'Tabitem25 = Gen Settings Full Tab
#Region "Gen String Settings"
    'Tabitem54 = Gen String Settings Full Tab
    'Tabitem37 = P1
    'Tabitem40 = P2
    'Tabitem45 = P3
    'Tabitem46 = P4
    'Tabitem47 = P5
    'Tabitem48 = P6
    'Tabitem49 = P7
    'Tabitem50 = P8
    'Tabitem51 = P9
    'Tabitem52 = P10
    'Tabitem53 = P11
#End Region
    'Tabitem26 = P1
    'Tabitem27 = P2
    'Tabitem36 = P3
#End Region
#Region "BackgroundWorkers Settings"
    'Tabitem4 = BackgroundWorkers Settings Full Tab
#End Region
    'Tabitem23 = P1
#End Region
#Region "Key Strings Settings"
    'Tabitem13 = Key Strings Settings Full Tab
    'Tabitem21 = P1
    'Tabitem22 = P2
#End Region
#End Region
#End Region
#Region "DIMS...ETC"
    Dim Key As String = "西こ比维吾き弗伊さふつまの德德ひむ艾ちゆに豆めた比つ艾か贼杰"
    Private CLFOLDER As String = "" + My.Application.Info.DirectoryPath + "\Program Files"
    Private rundum As String = "" + My.Application.Info.DirectoryPath + "\Program Files\List Names.txt"
    Private Shared __ENCList As List(Of WeakReference) = New List(Of WeakReference)()
    Public orn As List(Of String)
    Dim settings As New MySettings
#End Region
#Region "methods"
#Region ""
    Public Function EncryptSHA512Managed(ByVal rawstring As String) As String
        Dim sha512 As System.Security.Cryptography.SHA512 = New System.Security.Cryptography.SHA512Managed()
        Dim sha512Bytes As Byte() = System.Text.Encoding.Default.GetBytes(rawstring)
        Dim cryString As Byte() = sha512.ComputeHash(sha512Bytes)
        Dim sha512Str As String = String.Empty
        For i As Integer = 0 To cryString.Length - 1
            sha512Str += cryString(i).ToString("X")
        Next
        Return sha512Str
    End Function
    Public Function Md5FromString(ByVal rawString As String) As String

        Dim Bytes() As Byte
        Dim sb As New StringBuilder()

        If String.IsNullOrEmpty(rawString) Then
            Throw New ArgumentNullException
        End If
        Bytes = Encoding.Default.GetBytes(rawString)
        Bytes = MD5.Create().ComputeHash(Bytes)

        For x As Integer = 0 To Bytes.Length - 1
            sb.Append(Bytes(x).ToString("x2"))
        Next

        Return sb.ToString()

    End Function
    Public Function EncryptRJ256(ByVal prm_key As String, ByVal prm_iv As String, ByVal prm_text_to_encrypt As String)

        Dim sToEncrypt As String = prm_text_to_encrypt

        Dim myRijndael As New RijndaelManaged
        myRijndael.Padding = PaddingMode.Zeros
        myRijndael.Mode = CipherMode.CBC
        myRijndael.KeySize = 256
        myRijndael.BlockSize = 256

        Dim encrypted() As Byte
        Dim toEncrypt() As Byte
        Dim key() As Byte
        Dim IV() As Byte

        key = System.Text.Encoding.ASCII.GetBytes(prm_key)
        IV = System.Text.Encoding.ASCII.GetBytes(prm_iv)

        Dim encryptor As ICryptoTransform = myRijndael.CreateEncryptor(key, IV)

        Dim msEncrypt As New MemoryStream()
        Dim csEncrypt As New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)

        toEncrypt = System.Text.Encoding.ASCII.GetBytes(sToEncrypt)

        csEncrypt.Write(toEncrypt, 0, toEncrypt.Length)
        csEncrypt.FlushFinalBlock()

        encrypted = msEncrypt.ToArray()

        Return (Convert.ToBase64String(encrypted))

    End Function
    Public Function DecryptRJ256(ByVal prm_key As String, ByVal prm_iv As String, ByVal prm_text_to_decrypt As String)

        Dim sEncryptedString As String = prm_text_to_decrypt

        Dim myRijndael As New RijndaelManaged
        myRijndael.Padding = PaddingMode.Zeros
        myRijndael.Mode = CipherMode.CBC
        myRijndael.KeySize = 256
        myRijndael.BlockSize = 256

        Dim key() As Byte
        Dim IV() As Byte

        key = System.Text.Encoding.ASCII.GetBytes(prm_key)
        IV = System.Text.Encoding.ASCII.GetBytes(prm_iv)

        Dim decryptor As ICryptoTransform = myRijndael.CreateDecryptor(key, IV)

        Dim sEncrypted As Byte() = Convert.FromBase64String(sEncryptedString)

        Dim fromEncrypt() As Byte = New Byte(sEncrypted.Length) {}

        Dim msDecrypt As New MemoryStream(sEncrypted)
        Dim csDecrypt As New CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)

        csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length)

        Return (System.Text.Encoding.ASCII.GetString(fromEncrypt))

    End Function
    Private Shared Function Proper_RC4(ByVal Input As Byte(), ByVal Key As Byte()) As Byte()
        Dim i, j, swap As UInteger
        Dim s As UInteger() = New UInteger(255) {}
        Dim Output As Byte() = New Byte(Input.Length - 1) {}

        For i = 0 To 255
            s(i) = i
        Next

        For i = 0 To 255
            j = (j + Key(i Mod Key.Length) + s(i)) And 255
            swap = s(i) 'Swapping of s(i) and s(j)
            s(i) = s(j)
            s(j) = swap
        Next

        i = 0 : j = 0
        For c = 0 To Output.Length - 1
            i = (i + 1) And 255
            j = (j + s(i)) And 255
            swap = s(i) 'Swapping of s(i) and s(j)
            s(i) = s(j)
            s(j) = swap
            Output(c) = Input(c) Xor s((s(i) + s(j)) And 255)
        Next

        Return Output
    End Function
    Public Function AESEncryption(ByVal input As String, ByVal pass As String) As String
        Dim AES As New System.Security.Cryptography.RijndaelManaged
        Dim Hash_AES As New System.Security.Cryptography.MD5CryptoServiceProvider
        Dim encrypted As String = ""
        Try
            Dim hash(31) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESEncrypter As System.Security.Cryptography.ICryptoTransform = AES.CreateEncryptor
            Dim Buffer As Byte() = System.Text.ASCIIEncoding.ASCII.GetBytes(input)
            encrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return encrypted
        Catch ex As Exception
        End Try
    End Function

    Public Function AESDecryption(ByVal input As String, ByVal pass As String) As String
        Dim AES As New System.Security.Cryptography.RijndaelManaged
        Dim Hash_AES As New System.Security.Cryptography.MD5CryptoServiceProvider
        Dim decrypted As String = ""
        Try
            Dim hash(31) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESDecrypter As System.Security.Cryptography.ICryptoTransform = AES.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(input)
            decrypted = System.Text.ASCIIEncoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return decrypted
        Catch ex As Exception
        End Try
    End Function

    Private Function TruncateHash(
    ByVal key As String,
    ByVal length As Integer) As Byte()

        Dim sha1 As New SHA1CryptoServiceProvider

        ' Hash the key.
        Dim keyBytes() As Byte =
        System.Text.Encoding.Unicode.GetBytes(key)
        Dim hash() As Byte = sha1.ComputeHash(keyBytes)

        ' Truncate or pad the hash.
        ReDim Preserve hash(length - 1)
        Return hash
    End Function


#End Region
#Region "random"
    'Compression(GZip)
    Public Function Zip_Grandom() As String
        Dim random As Random = New Random()
        Dim text As String = Zip_G(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown15.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Compression(Deflate)
    Public Function Zip_deflaterandom() As String
        Dim random As Random = New Random()
        Dim text As String = Zip_deflate(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown16.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    '~Draven's Algorithm
    Public Function CryptString_1random() As String
        Dim random As Random = New Random()
        Dim text As String = CryptString_1(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown17.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'converttoline
    Public Function converttolinerandom() As String
        Dim random As Random = New Random()
        Dim text As String = converttoline(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown18.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Custom Line
    Public Function Encrypt_CustomLinerandom() As String
        Dim random As Random = New Random()
        Dim text As String = Encrypt_CustomLine(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown19.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Binary
    Public Function binaryrandom() As String
        Dim random As Random = New Random()
        Dim text As String = ConvertToBinary(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown20.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'HEX
    Public Function HEXrandom() As String
        Dim random As Random = New Random()
        Dim text As String = String2Hex(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown21.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'pr0t3
    Public Function pr0t3random() As String
        Dim random As Random = New Random()
        Dim text As String = pr0t3_encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown22.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'RSA
    Public Function RSArandom() As String
        Dim random As Random = New Random()
        Dim text As String = RSA_Encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown23.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Rot13
    Public Function Rot13random() As String
        Dim random As Random = New Random()
        Dim text As String = Rot13(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown24.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'BASE64
    Public Function BASE64random() As String
        Dim random As Random = New Random()
        Dim text As String = BASE64_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown25.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'MEGAN35
    Public Function MEGAN35random() As String
        Dim random As Random = New Random()
        Dim text As String = MEGAN35_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown26.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'ZONG22
    Public Function ZONG22random() As String
        Dim random As Random = New Random()
        Dim text As String = ZONG22_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown27.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'TRIPO5
    Public Function TRIPO5random() As String
        Dim random As Random = New Random()
        Dim text As String = TRIPO5_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown28.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'TIGO3FX
    Public Function TIGO3FXrandom() As String
        Dim random As Random = New Random()
        Dim text As String = TIGO3FX_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown29.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'FERON74
    Public Function FERON74random() As String
        Dim random As Random = New Random()
        Dim text As String = FERON74_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown30.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'ESAB46
    Public Function ESAB46random() As String
        Dim random As Random = New Random()
        Dim text As String = ESAB46_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown31.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'GILA7
    Public Function GILA7random() As String
        Dim random As Random = New Random()
        Dim text As String = GILA7_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown32.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Atom128
    Public Function Atom128random() As String
        Dim random As Random = New Random()
        Dim text As String = Atom128_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown34.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'HAZZ15
    Public Function HAZZ15random() As String
        Dim random As Random = New Random()
        Dim text As String = HAZZ15_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown33.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Atbash_Cipher
    Public Function Atbash_Cipherrandom() As String
        Dim random As Random = New Random()
        Dim text As String = Atbash_Cipher(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown35.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'ZARA128
    Public Function ZARA128random() As String
        Dim random As Random = New Random()
        Dim text As String = ZARA128_Encode(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown36.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'ARMON64
    Public Function ARMON64random() As String
        Dim random As Random = New Random()
        Dim text As String = ARMON64_Encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown37.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'Encrypt
    Public Function Encryptrandom() As String
        Dim random As Random = New Random()
        Dim text As String = Encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown38.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'AER256
    Public Function AER256random() As String
        Dim random As Random = New Random()
        Dim text As String = AER256_Encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown41.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    'EncryptData
    Public Function EncryptDatarandom() As String
        Dim random As Random = New Random()
        Dim text As String = EncryptData(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown42.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function EncryptData(
    ByVal plaintext As String) As String

        ' Convert the plaintext string to a byte array.
        Dim plaintextBytes() As Byte =
        System.Text.Encoding.Unicode.GetBytes(plaintext)

        ' Create the stream.
        Dim ms As New System.IO.MemoryStream
        ' Create the encoder to write to the stream.
        Dim encStream As New CryptoStream(ms,
        TripleDes.CreateEncryptor(),
        System.Security.Cryptography.CryptoStreamMode.Write)

        ' Use the crypto stream to write the byte array to the stream.
        encStream.Write(plaintextBytes, 0, plaintextBytes.Length)
        encStream.FlushFinalBlock()

        ' Convert the encrypted stream to a printable string.
        Return Convert.ToBase64String(ms.ToArray)
    End Function
    Private TripleDes As New TripleDESCryptoServiceProvider
    'EncryptData
    Public Function HMACMD5() As String
        Dim random As Random = New Random()
        Dim text As String = HMACMD5(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown47.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function HMACRIPEMD160() As String
        Dim random As Random = New Random()
        Dim text As String = HMACRIPEMD160(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown48.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function HMACSHA1() As String
        Dim random As Random = New Random()
        Dim text As String = HMACSHA1(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown49.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function HMACSHA256() As String
        Dim random As Random = New Random()
        Dim text As String = HMACSHA256(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown50.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function HMACSHA384() As String
        Dim random As Random = New Random()
        Dim text As String = HMACSHA384(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown51.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function HMACSHA512() As String
        Dim random As Random = New Random()
        Dim text As String = HMACSHA512(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown52.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function MACTripleDES() As String
        Dim random As Random = New Random()
        Dim text As String = MACTripleDES(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown53.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function MD5_64() As String
        Dim random As Random = New Random()
        Dim text As String = MD5_64(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown54.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function EncryptSHA512Managed() As String
        Dim random As Random = New Random()
        Dim text As String = EncryptSHA512Managed(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown55.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function rc4() As String
        Dim random As Random = New Random()
        Dim text As String = rc4(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown56.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function THIRD_DES() As String
        Dim random As Random = New Random()
        Dim text As String = EncryptString(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown57.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function AES() As String
        Dim random As Random = New Random()
        Dim text As String = AES_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown58.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function CeaserChipher() As String
        Dim random As Random = New Random()
        Dim text As String = c_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown59.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function CustomXOR() As String
        Dim random As Random = New Random()
        Dim text As String = CustomXOR_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown60.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function DES() As String
        Dim random As Random = New Random()
        Dim text As String = DES_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown61.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function Envy() As String
        Dim random As Random = New Random()
        Dim text As String = EnvY_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown62.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function PolymorphicRC4() As String
        Dim random As Random = New Random()
        Dim x As New PolyRC4(random.[Next])
        Dim text As String = x.Encrypt(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown63.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function PolymorphicStairs() As String
        Dim random As Random = New Random()
        Dim text As String = PolyCrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown64.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function rc2() As String
        Dim random As Random = New Random()
        Dim text As String = RC2Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown65.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function rc4random() As String
        Dim random As Random = New Random()
        Dim text As String = rc4(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown66.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function Rijndael() As String
        Dim random As Random = New Random()
        Dim text As String = Rijndaelcrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown67.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function Stairs() As String
        Dim random As Random = New Random()
        Dim text As String = Crypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown68.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function TripleDESrand() As String
        Dim random As Random = New Random()
        Dim text As String = TripleDES_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown69.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function Vernam() As String
        Dim random As Random = New Random()
        Dim text As String = vernam1.x(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown70.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function XORrandom() As String
        Dim random As Random = New Random()
        Dim text As String = XOR_Encrypt(random.[Next], random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown71.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
#End Region
#Region "rundom"
    Function SearchChar(ByVal Character As String) As Integer
        For I = 0 To 255
            If Chr(I) = Character Then
                Return I
            End If
        Next I
    End Function
    Public Function ReverseString(ByRef strToReverse As String) As String
        Dim result As String = ""
        For i As Integer = 0 To strToReverse.Length - 1
            result += strToReverse(strToReverse.Length - 1 - i)
        Next
        Return result
    End Function
    Function Vigenere_Cipher(ByVal Text As String, ByVal key As String, ByVal Encrypt As Boolean)
        Dim Result As String = ""
        Dim temp As String = ""
        Dim j As Integer = 0
        For i As Integer = 0 To Text.Length - 1
            If j = key.Length Then
                j = 0
            End If
            If Char.IsLetter(key(j)) Then
                If Text(i) <> " " And Char.IsLetter(Text(i)) Then
                    temp += key(j)
                    j += 1
                Else
                    temp += Text(i)
                End If
            Else
                j += 1
                If j >= key.Length Then
                    j = 0
                End If
                i -= 1
            End If
        Next
        For i As Integer = 0 To Text.Length - 1
            Dim N As Integer
            Dim NewAscii As Integer
            If Char.IsLetter(Text(i)) Then
                If Char.IsLower(temp(i)) Then
                    N = Asc(temp(i)) - Asc("a")
                ElseIf Char.IsUpper(temp(i)) Then
                    N = Asc(temp(i)) - Asc("A")
                End If
                If Encrypt Then
                    NewAscii = N + Asc(Text(i))
                Else
                    NewAscii = 26 - N + Asc(Text(i))
                End If
                If (NewAscii > Asc("z") And Char.IsLower(Text(i))) Or (NewAscii > Asc("Z") And Char.IsUpper(Text(i))) Then
                    NewAscii -= 26
                End If
            Else
                NewAscii = Asc(Text(i))
            End If
            Result += Chr(NewAscii)
        Next
        Return Result
    End Function

    Public Function RNP() As String
        Dim random As Random = New Random()
        Dim text As String = "ABCDEFGHIJKLMNOPQRSTUVXWYZ0123456789abcdefghijklmnopqrstuvxyz" & ChrW(2350) & ChrW(2354) & ChrW(2366) & ChrW(2312) & ChrW(2360) & ChrW(2350) & ChrW(2381) & ChrW(2333) & ChrW(2344) & ChrW(2366) & ChrW(2350) & ChrW(2369) & ChrW(2333) & ChrW(2375) & ChrW(2351) & ChrW(2366) & ChrW(2342) & ChrW(2352) & ChrW(2326) & ChrW(2344) & ChrW(2366) & ChrW(920) & ChrW(965) & ChrW(956) & ChrW(942) & ChrW(963) & ChrW(959) & ChrW(965) & ChrW(956) & ChrW(949) & ChrW(3240) & ChrW(3240) & ChrW(3277) & ChrW(3240) & ChrW(3240) & ChrW(3277) & ChrW(3240) & ChrW(3265) & ChrW(3240) & ChrW(3270) & ChrW(3240) & ChrW(3242) & ChrW(3263) & ChrW(3240) & ChrW(3250) & ChrW(3277) & ChrW(3250) & ChrW(3263) & ChrW(3512) & ChrW(3535) & ChrW(3520) & ChrW(3512) & ChrW(3501) & ChrW(3482) & ChrW(3501) & ChrW(3510) & ChrW(3535) & ChrW(3484) & ChrW(3505) & ChrW(3530) & ChrW(3505) & ChrW(2606) & ChrW(2631) & ChrW(2608) & ChrW(2624) & ChrW(4100) & ChrW(4139) & ChrW(4151) & ChrW(4096) & ChrW(4141) & ChrW(4143) & ChrW(4126) & ChrW(4112) & ChrW(4141) & ChrW(4123) & ChrW(4117) & ChrW(4139) & ChrW(2607) & ChrW(2622) & ChrW(2598) & ChrW(2617) & ChrW(2632) & ChrW(3207) & ChrW(3233) & ChrW(3265) & ChrW(4307) & ChrW(4304) & ChrW(4315) & ChrW(4312) & ChrW(4315) & ChrW(4304) & ChrW(4334) & ChrW(4321) & ChrW(4317) & ChrW(4309) & ChrW(4320) & ChrW(4308) & ChrW(1490) & ChrW(1506) & ChrW(1491) & ChrW(1506) & ChrW(1504) & ChrW(1511) & ChrW(45216) & ChrW(3720) & ChrW(3767) & ChrW(3784) & ChrW(8203) & ChrW(3714) & ChrW(3785) & ChrW(3757) & ChrW(3725) & ChrW(3342) & ChrW(3368) & ChrW(3405) & ChrW(3368) & ChrW(3398) & ChrW(1047) & ChrW(1072) & ChrW(1087) & ChrW(1086) & ChrW(1084) & ChrW(1085) & ChrW(1080) & ChrW(1081) & ChrW(35352) & ChrW(20303) & ChrW(25105) & ChrW(35760) & ChrW(20303) & ChrW(25105) & ChrW(1105) & ChrW(1076) & ChrW(1494) & ChrW(1499) & ChrW(1493) & ChrW(1512) & ChrW(2734) & ChrW(2728) & ChrW(2759) & ChrW(7899) & ChrW(1179) & ChrW(2735) & ChrW(2750) & ChrW(2726) & ChrW(1488) & ChrW(1493) & ChrW(1514) & ChrW(1497) & ChrW(1076) & ChrW(1084) & ChrW(1077) & ChrW(3347) & ChrW(3452) & ChrW(3349) & ChrW(3405) & ChrW(3349) & ChrW(3363) & ChrW(3330) & ChrW(44592) & ChrW(50613) & ChrW(54644) & ChrW(1502) & ChrW(1497) & ChrW(1498) & ChrW(31169) & ChrW(12434) & ChrW(35226) & ChrW(12360) & ChrW(12390) & ChrW(12414) & ChrW(12377) & ChrW(12363) & ChrW(1571) & ChrW(1576) & ChrW(1578) & ChrW(1579) & ChrW(1580) & ChrW(1581) & ChrW(1582) & ChrW(1583) & ChrW(1584) & ChrW(1585) & ChrW(1586) & ChrW(1587) & ChrW(1588) & ChrW(1589) & ChrW(1590) & ChrW(1591) & ChrW(1592) & ChrW(1593) & ChrW(1594) & ChrW(1601) & ChrW(1602) & ChrW(1603) & ChrW(1604) & ChrW(1605) & ChrW(1606) & ChrW(1607) & ChrW(1608) & ChrW(1610)
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown2.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function SHA1Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = SHA1Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown10.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function SHA256Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = SHA256Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown11.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function SHA348Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = SHA348Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown12.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function SHA512Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = SHA512Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown13.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function RIPEMD160Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = RIPEMD160Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown14.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function MD5Hashrandom() As String
        Dim random As Random = New Random()
        Dim text As String = MD5Hash(random.[Next])
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown9.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function RNM() As String
        Dim random As Random = New Random()
        Dim text As String = TextBoxX7.Text
        Dim text2 As String = Nothing
        Dim arg_1C_0 As Integer = 0
        Dim value As Integer = Me.NumericUpDown3.Value
        For i As Integer = arg_1C_0 To value
            text2 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text2
    End Function
    Public Function RN() As String
        Dim text As String
        Do
            Dim random As Random = New Random()
            text = ""
            Dim text2 As String = ChrW(44592) & ChrW(50613) & ChrW(54644) & ChrW(1502) & ChrW(1497) & ChrW(1498) & ChrW(31169) & ChrW(12434) & ChrW(35226) & ChrW(12360) & ChrW(12390) & ChrW(12414) & ChrW(12377) & ChrW(12363) & ChrW(1571) & ChrW(1576) & ChrW(1578) & ChrW(1579) & ChrW(1580) & ChrW(1581) & ChrW(1582) & ChrW(1583) & ChrW(1584) & ChrW(1585) & ChrW(1586) & ChrW(1587) & ChrW(1588) & ChrW(1589) & ChrW(1590) & ChrW(1591) & ChrW(1592) & ChrW(1593) & ChrW(1594) & ChrW(1601) & ChrW(1602) & ChrW(1603) & ChrW(1604) & ChrW(1605) & ChrW(1606) & ChrW(1607) & ChrW(1608) & ChrW(1610)
            Dim num As Integer = random.[Next](1, 10)
            For i As Integer = 1 To num
                text += Convert.ToString(text2(random.[Next](0, text2.Length)))
            Next
        Loop While orn.Contains(text)
        orn.Add(text)
        Return text
    End Function
    Public Function RNV(N As Long) As String
        Dim random As Random = New Random()
        Dim text As String = TextBox21.Text
        Dim text2 As String = TextBox36.Text
        Dim text3 As String = Nothing
        Dim num As Integer = 0
        Do
            text3 += Conversions.ToString(text2(random.[Next](text2.Length)))
            num += 1
        Loop While num <= 3
        For num2 As Long = 0L To N
            text3 += Conversions.ToString(text(random.[Next](text.Length)))
        Next
        Return text3
    End Function
    Public Function PTES2E(S As String, M As String) As Object
        Dim arg_08_0 As Integer = 1
        Dim length As Integer = S.Length
        For i As Integer = arg_08_0 To length
            StringType.MidStmtStr(S, i, 1, Conversions.ToString(ChrW(AscW(Mid(S, i, 1)) + 36864 - M.Length)))
        Next
        Return S
    End Function
    Public Shared Function RNG(byte_0 As Byte()) As Byte()
        Dim rngcryptoServiceProvider As RNGCryptoServiceProvider = New RNGCryptoServiceProvider()
        Dim array As Byte() = New Byte(31) {}
        ' The following expression was wrapped in a checked-statement
        Dim array2 As Byte() = New Byte(32 + (byte_0.Length - 1) + 1 - 1 + 1 - 1 + 1 - 1) {}
        rngcryptoServiceProvider.GetBytes(array)
        Buffer.BlockCopy(array, 0, array2, 0, 32)
        Buffer.BlockCopy(byte_0, 0, array2, 32, byte_0.Length)
        Dim num As Integer = array2.Length - 1
        For i As Integer = 32 To num
            array2(i) = array2(i) Xor array(i Mod array.Length)
        Next
        Return array2
    End Function
    Public Function GenerateUniqueString(ByVal len As Integer) As String
        Dim rnd As Random
        Dim str, result As String
        rnd = New Random
        str = TextBox37.Text
        result = ""
        While len > 0
            result &= str.Chars(rnd.Next(0, str.Length - 1))
            len -= 1
        End While
        Return result
    End Function
    Public Shared Function GetUniqueKey(maxSize As Integer) As String
        Dim array As Char() = New Char(61) {}
        Dim checked As Boolean = My.Forms.JamesrebornsProtections.RadioButton12.Checked
        If checked Then
            array = ChrW(1575) & ChrW(1571) & ChrW(1573) & ChrW(1576) & ChrW(1578) & ChrW(1579) & ChrW(1580) & ChrW(1581) & ChrW(1582) & ChrW(1583) & ChrW(1584) & ChrW(1585) & ChrW(1586) & ChrW(1587) & ChrW(1588) & ChrW(1589) & ChrW(1590) & ChrW(1591) & ChrW(1592) & ChrW(1593) & ChrW(1594) & ChrW(1601) & ChrW(1602) & ChrW(1603) & ChrW(1604) & ChrW(1605) & ChrW(1606) & ChrW(1607) & ChrW(1608) & ChrW(1609) & ChrW(1604) & ChrW(1575)
        End If
        checked = My.Forms.JamesrebornsProtections.RadioButton13.Checked
        If checked Then
            array = Conversions.ToCharArrayRankOne(ChrW(1041) & ChrW(1105) & ChrW(1043) & ChrW(1044) & ChrW(1046) & ChrW(1047) & ChrW(1048) & ChrW(1049) & ChrW(1051) & ChrW(1073) & ChrW(1075) & ChrW(1076) & ChrW(1078) & ChrW(1079) & ChrW(1080) & ChrW(1081) & ChrW(1082) & ChrW(1083) & ChrW(1055) & ChrW(1060) & ChrW(1061) & ChrW(1062) & ChrW(1063) & ChrW(1064) & ChrW(1065) & ChrW(1066) & ChrW(1068) & ChrW(1070) & ChrW(1071) & ChrW(1085) & ChrW(1086) & ChrW(1087) & ChrW(1092) & ChrW(1093) & ChrW(1094) & ChrW(1095) & ChrW(1096) & ChrW(1097) & ChrW(1098) & ChrW(1100) & ChrW(1102) & ChrW(1103) & ChrW(1122) & ChrW(1130) & ChrW(1123) & ChrW(1131))
        End If
        checked = My.Forms.JamesrebornsProtections.RadioButton14.Checked
        If checked Then
            array = ChrW(33521) & ChrW(25991) & ChrW(20070) & ChrW(20449) & ChrW(20013) & ChrW(19977) & ChrW(21313) & ChrW(20313) & ChrW(31181) & ChrW(34920) & ChrW(36798) & ChrW(35874) & ChrW(35874) & ChrW(30340) & ChrW(26041) & ChrW(24335) & ChrW(38750) & ChrW(24120) & ChrW(24863) & ChrW(35874) & ChrW(29992) & ChrW(33521) & ChrW(25991) & ChrW(24590) & ChrW(20040) & ChrW(35828) & ChrW(22825) & ChrW(28079) & ChrW(38382) & ChrW(31572) & ChrW(22806) & ChrW(35821) & ChrW(39057) & ChrW(36947) & ChrW(20313) & ChrW(31181) & ChrW(34920) & ChrW(36798) & ChrW(35874) & ChrW(30340) & ChrW(26041) & ChrW(24335) & ChrW(33258) & ChrW(20266) & ChrW(20249) & ChrW(20223) & ChrW(20208) & ChrW(21326) & ChrW(20221) & ChrW(20215) & ChrW(24310) & ChrW(20240) & ChrW(20239) & ChrW(20051) & ChrW(20256) & ChrW(20255) & ChrW(20002) & ChrW(20808) & ChrW(32905) & ChrW(24180)
        End If
        checked = My.Forms.JamesrebornsProtections.RadioButton11.Checked
        If checked Then
            array = Conversions.ToCharArrayRankOne("AaBaCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz")
        End If
        Dim array2 As Byte() = New Byte(0) {}
        Dim rNGCryptoServiceProvider As RNGCryptoServiceProvider = New RNGCryptoServiceProvider()
        rNGCryptoServiceProvider.GetNonZeroBytes(array2)
        ' The following expression was wrapped in a checked-statement
        array2 = New Byte(maxSize - 1 + 1 - 1) {}
        rNGCryptoServiceProvider.GetNonZeroBytes(array2)
        Dim stringBuilder As StringBuilder = New StringBuilder(maxSize)
        Dim array3 As Byte() = array2
        For i As Integer = 0 To array3.Length - 1
            Dim b As Byte = array3(i)
            stringBuilder.Append(array(CInt(b) Mod array.Length))
        Next
        Return stringBuilder.ToString()
    End Function
#End Region
#Region "UNKNOWN"
    Public Function Encrypt(ByVal plainText As String) As String
        Dim passPhrase As String = TextBoxX48.Text
        Dim saltValue As String = TextBoxX49.Text
        Dim hashAlgorithm As String = TextBoxX50.Text

        Dim passwordIterations As Integer = NumericUpDown39.Value
        Dim initVector As String = TextBoxX51.Text
        Dim keySize As Integer = NumericUpDown40.Value

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)

        Dim plainTextBytes As Byte() = Encoding.UTF8.GetBytes(plainText)


        Dim password As New PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations)

        Dim keyBytes As Byte() = password.GetBytes(keySize \ 8)
        Dim symmetricKey As New RijndaelManaged()

        symmetricKey.Mode = CipherMode.CBC

        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)

        Dim memoryStream As New MemoryStream()
        Dim cryptoStream As New CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)

        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
        cryptoStream.FlushFinalBlock()
        Dim cipherTextBytes As Byte() = memoryStream.ToArray()
        memoryStream.Close()
        cryptoStream.Close()
        Dim cipherText As String = Convert.ToBase64String(cipherTextBytes)
        Return cipherText
    End Function
    Public Function Decrypt(ByVal cipherText As String) As String
        Dim passPhrase As String = TextBoxX48.Text
        Dim saltValue As String = TextBoxX49.Text
        Dim hashAlgorithm As String = TextBoxX50.Text

        Dim passwordIterations As Integer = NumericUpDown39.Value
        Dim initVector As String = TextBoxX51.Text
        Dim keySize As Integer = NumericUpDown40.Value
        ' Convert strings defining encryption key characteristics into byte
        ' arrays. Let us assume that strings only contain ASCII codes.
        ' If strings include Unicode characters, use Unicode, UTF7, or UTF8
        ' encoding.
        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)

        ' Convert our ciphertext into a byte array.
        Dim cipherTextBytes As Byte() = Convert.FromBase64String(cipherText)

        ' First, we must create a password, from which the key will be 
        ' derived. This password will be generated from the specified 
        ' passphrase and salt value. The password will be created using
        ' the specified hash algorithm. Password creation can be done in
        ' several iterations.
        Dim password As New PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations)

        ' Use the password to generate pseudo-random bytes for the encryption
        ' key. Specify the size of the key in bytes (instead of bits).
        Dim keyBytes As Byte() = password.GetBytes(keySize \ 8)

        ' Create uninitialized Rijndael encryption object.
        Dim symmetricKey As New RijndaelManaged()

        ' It is reasonable to set encryption mode to Cipher Block Chaining
        ' (CBC). Use default options for other symmetric key parameters.
        symmetricKey.Mode = CipherMode.CBC

        ' Generate decryptor from the existing key bytes and initialization 
        ' vector. Key size will be defined based on the number of the key 
        ' bytes.
        Dim decryptor As ICryptoTransform = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        ' Define memory stream which will be used to hold encrypted data.
        Dim memoryStream As New MemoryStream(cipherTextBytes)

        ' Define cryptographic stream (always use Read mode for encryption).
        Dim cryptoStream As New CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)

        ' Since at this point we don't know what the size of decrypted data
        ' will be, allocate the buffer long enough to hold ciphertext;
        ' plaintext is never longer than ciphertext.
        Dim plainTextBytes As Byte() = New Byte(cipherTextBytes.Length - 1) {}

        ' Start decrypting.
        Dim decryptedByteCount As Integer = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length)

        ' Close both streams.
        memoryStream.Close()
        cryptoStream.Close()

        ' Convert decrypted data into a string. 
        ' Let us assume that the original plaintext string was UTF8-encoded.
        Dim plainText As String = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount)

        ' Return decrypted string.   
        Return plainText
    End Function

#End Region
#Region "new stuff to fuck with"
    Private encoder As UTF8Encoding
    Public Function MD5_64(input As String) As String
        Dim mD As MD5 = MD5.Create()
        Dim bytes As Byte() = Encoding.ASCII.GetBytes(input)
        Dim array As Byte() = mD.ComputeHash(bytes)
        Dim stringBuilder As StringBuilder = New StringBuilder()
        Dim arg_2A_0 As Integer = 0
        ' The following expression was wrapped in a checked-statement
        Dim num As Integer = array.Length - 1
        Dim num2 As Integer = arg_2A_0
        While True
            Dim arg_57_0 As Integer = num2
            Dim num3 As Integer = num
            If arg_57_0 > num3 Then
                Exit While
            End If
            stringBuilder.Append(array(num2).ToString("X2"))
            num2 += 1
        End While
        Return stringBuilder.ToString()
    End Function
    Public Function Obfuscate_Encode(sInput As String) As String
        Dim text As String = ""
        Dim length As Integer = sInput.Length
        Dim num As Integer = length
        ' The following expression was wrapped in a checked-statement
        While True
            Dim arg_2D_0 As Integer = num
            Dim num2 As Integer = 1
            If arg_2D_0 < num2 Then
                Exit While
            End If
            text += Strings.Mid(sInput, num, 1)
            num += -2
        End While
        num = length - 1
        While True
            Dim arg_50_0 As Integer = num
            Dim num2 As Integer = 1
            If arg_50_0 < num2 Then
                Exit While
            End If
            text += Strings.Mid(sInput, num, 1)
            num += -2
        End While
        Return text
    End Function
    Public Function Obfuscate_Decode(sInput As String) As String
        Dim text As String = ""
        Dim length As Integer = sInput.Length
        Dim num As Integer = length Mod 2
        Dim num2 As Integer = length / 2
        ' The following expression was wrapped in a checked-statement
        Dim num3 As Integer = num2 + num
        While True
            Dim arg_8B_0 As Integer = num3
            Dim num4 As Integer = 1
            If arg_8B_0 < num4 Then
                Exit While
            End If
            Dim flag As Boolean = num = 0
            If flag Then
                text += Strings.Mid(sInput, num3 + num2, 1)
            End If
            text += Strings.Mid(sInput, num3, 1)
            flag = (num = 1 And num3 <> 1)
            If flag Then
                text += Strings.Mid(sInput, num3 + num2, 1)
            End If
            num3 += -1
        End While
        Return text
    End Function
    Private source As String
    Public Function Random() As String
        Me.source = ""
        Dim counter As Object
        Dim loopObj As Object
        Dim flag As Boolean = ObjectFlowControl.ForLoopControl.ForLoopInitObj(counter, 1, 16, 1, loopObj, counter)
        If flag Then
            Do
                VBMath.Randomize()
                Dim value As Object = Conversion.Int(VBMath.Rnd() * 66.0F + 1.0F)
                Me.source += Strings.Mid("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", Conversions.ToInteger(value), 1)
            Loop While ObjectFlowControl.ForLoopControl.ForNextCheckObj(counter, loopObj, counter)
        End If
        Return Me.source
    End Function
    Public Function generate(source As String, message As String) As String
        Dim text As String = Conversions.ToString(source.Length)
        Dim flag As Boolean = text.Length >= 44
        If flag Then
            text = Conversions.ToString(44)
        End If
        source = (New String() {Nothing, "a", "e", "$", "]", "l", "d", "k", "c", "j", "#", "j", "z", "@", "f", "!", "h", "w", ":", "g", "x", "s", "y", "o", "`", "*", "p", "~", "q", "/", "u", "?", "v", "(", "+", ")", "=", "}", "|", "{", "3", "8", "5", "2", "4"})(Conversions.ToInteger(text))
        Return source
    End Function
    Public Function XRay(message As String, password As String) As String
        Dim num As Integer = 0
        Dim value As String = Conversions.ToString(message.Length)
        Dim arg_1C_0 As Integer = 1
        ' The following expression was wrapped in a checked-statement
        Dim num2 As Integer = 31 - message.Length
        Dim num3 As Integer = arg_1C_0
        While True
            Dim arg_3F_0 As Integer = num3
            Dim num4 As Integer = num2
            If arg_3F_0 > num4 Then
                Exit While
            End If
            message += Me.generate(message, password)
            num3 += 1
        End While
        Dim array As String() = New String(32) {}
        array(1) = Conversions.ToString(913021)
        array(2) = Conversions.ToString(314712)
        array(3) = Conversions.ToString(125631)
        array(4) = Conversions.ToString(464123)
        array(5) = Conversions.ToString(239975)
        array(3) = Conversions.ToString(288845)
        array(7) = Conversions.ToString(437745)
        array(8) = Conversions.ToString(444935)
        array(9) = Conversions.ToString(779288)
        array(10) = Conversions.ToString(99618)
        array(11) = Conversions.ToString(47144)
        array(12) = Conversions.ToString(18323)
        array(13) = Conversions.ToString(87115)
        array(14) = Conversions.ToString(78426)
        array(15) = Conversions.ToString(64767)
        array(16) = Conversions.ToString(77878)
        array(17) = Conversions.ToString(19942)
        array(18) = Conversions.ToString(27546)
        array(19) = Conversions.ToString(86146)
        array(20) = Conversions.ToString(42183)
        array(21) = Conversions.ToString(64387)
        array(22) = Conversions.ToString(87973)
        array(23) = Conversions.ToString(19843)
        array(24) = Conversions.ToString(76514)
        array(25) = Conversions.ToString(19526)
        array(26) = Conversions.ToString(99737)
        array(27) = Conversions.ToString(67452)
        array(28) = Conversions.ToString(74972)
        array(29) = Conversions.ToString(17786)
        array(30) = Conversions.ToString(97942)
        array(31) = Conversions.ToString(56444)
        array(32) = Conversions.ToString(44176)
        Dim flag As Boolean = Conversions.ToDouble(value) >= 33.0
        If flag Then
            num = 32
        End If
        num = Conversions.ToInteger(array(num))
        Dim num5 As Integer = 0
        Dim num6 As Integer = 0
        Dim i As Integer = 0
        Dim j As Integer = 0
        Dim k As Integer = 0
        Dim num7 As Integer = 0
        Dim l As Integer = 0
        Dim array2 As Integer() = New Integer(256) {}
        Dim array3 As Integer() = New Integer(256) {}
        Dim array4 As Integer() = New Integer(256) {}
        Dim array5 As Integer() = New Integer(256) {}
        Dim stringBuilder As StringBuilder = New StringBuilder()
        Dim empty As String = String.Empty
        Dim text As String = message
        Dim m As Integer = 0
        Dim length As Integer = text.Length
        Dim text2 As String
        While m < length
            Dim [string] As Char = text(m)
            ' The following expression was wrapped in a unchecked-expression
            text2 = Conversions.ToString(Conversions.ToDouble(text2) + CDbl(Strings.Asc([string])))
            m += 1
        End While
        Dim n As Integer = 0
        Dim length2 As Integer = password.Length
        Dim value2 As String
        Dim value3 As String
        While n < length2
            Dim string2 As Char = password(n)
            ' The following expression was wrapped in a unchecked-expression
            value2 = Conversions.ToString(Conversions.ToDouble(value2) + CDbl(Strings.Asc(string2)))
            While l < password.Length
                ' The following expression was wrapped in a unchecked-expression
                value3 = Conversions.ToString(Conversions.ToDouble(value3) + Math.Pow(CDbl(l), CDbl(password.Length)))
                l += 1
            End While
            n += 1
        End While
        While i <= password.Length
            ' The following expression was wrapped in a unchecked-expression
            ' The following expression was wrapped in a checked-expression
            Dim value4 As String = Conversions.ToString(Conversions.ToDouble(value4) + (Conversions.ToDouble(value2) * 3.0 + CDbl((password.Length + Strings.Asc(message)))))
            i += 1
        End While
        While j <= 255
            Dim string3 As Char = password.Substring(j Mod password.Length, 1).ToCharArray()(0)
            array3(j) = Strings.Asc(string3)
            array2(j) = j
            Math.Max(Interlocked.Increment(j), j - 1)
        End While
        While k <= 255
            num7 = (num7 + array2(k) + (array3(k) + num)) Mod 256
            Dim num8 As Integer = array2(k)
            array2(k) = array2(num7) Mod 256
            array2(num7) = num8 Mod 256
            Math.Max(Interlocked.Increment(k), k - 1)
        End While
        j = 1
        Dim value5 As String = text2
        While j <= message.Length
            num5 = (num5 + 1 + (i + num)) Mod 256
            num6 = (num6 + array2(num5)) Mod 256
            ' The following expression was wrapped in a unchecked-expression
            Dim num9 As Integer = CInt(Math.Round(CDbl(array4(j)) + Conversions.ToDouble(value5) + CDbl(password.Length) Mod 256.0))
            ' The following expression was wrapped in a unchecked-expression
            array2(num5) = CInt(Math.Round(CDbl(array2(num6)) + (Conversions.ToDouble(value2) + 71.0) Mod 256.0))
            ' The following expression was wrapped in a unchecked-expression
            array2(num6) = CInt(Math.Round(CDbl(num) + Conversions.ToDouble(value3) Mod 256.0))
            ' The following expression was wrapped in a unchecked-expression
            array4(num5) = CInt(Math.Round(CDbl(array4(num6)) + CDbl(num) / 2.0 Mod 256.0))
            ' The following expression was wrapped in a unchecked-expression
            ' The following expression was wrapped in a checked-expression
            array4(num6) = CInt(Math.Round(CDbl(array4(num5)) + Conversions.ToDouble(text2) + CDbl((array2(num6) + num)) + Math.Pow(Conversions.ToDouble(text2), 2.0) Mod 256.0))
            ' The following expression was wrapped in a unchecked-expression
            Dim num10 As Integer = array2(CInt(Math.Round(CDbl(array2(num5)) + Conversions.ToDouble(text2) Mod 256.0)))
            Dim string4 As Char = message.Substring(j - 1, 1).ToCharArray()(0)
            num9 = Strings.Asc(string4)
            Dim charCode As Integer = num9 Xor num10
            stringBuilder.Append(Strings.Chr(charCode))
            Math.Max(Interlocked.Increment(j), j - 1)
        End While
        Return stringBuilder.ToString()
    End Function
    Public Function EncryptX(TheText As String) As String
        Dim arg_09_0 As Integer = 1
        Dim num As Integer = Strings.Len(TheText)
        Dim num2 As Integer = arg_09_0
        ' The following expression was wrapped in a checked-statement
        Dim text As String
        While True
            Dim arg_3F_0 As Integer = num2
            Dim num3 As Integer = num
            If arg_3F_0 > num3 Then
                Exit While
            End If
            text += Conversions.ToString(Strings.Chr(Strings.Asc(Strings.Mid(Strings.StrReverse(TheText), num2, 1)) + Strings.Len(TheText)))
            num2 += 1
        End While
        Return text
    End Function

    Public Function DecryptX(TheText As String) As String
        Dim arg_09_0 As Integer = 1
        Dim num As Integer = Strings.Len(TheText)
        Dim num2 As Integer = arg_09_0
        ' The following expression was wrapped in a checked-statement
        Dim text As String
        While True
            Dim arg_3F_0 As Integer = num2
            Dim num3 As Integer = num
            If arg_3F_0 > num3 Then
                Exit While
            End If
            text += Conversions.ToString(Strings.Chr(Strings.Asc(Strings.Mid(Strings.StrReverse(TheText), num2, 1)) - Strings.Len(TheText)))
            num2 += 1
        End While
        Return text
    End Function

    Public Function SimpleEncrypt(TheText As String) As String
        Dim text As String = ""
        Dim arg_13_0 As Integer = 1
        Dim num As Integer = Strings.Len(TheText)
        Dim num2 As Integer = arg_13_0
        ' The following expression was wrapped in a checked-statement
        While True
            Dim arg_4B_0 As Integer = num2
            Dim num3 As Integer = num
            If arg_4B_0 > num3 Then
                Exit While
            End If
            Dim str As String = Conversions.ToString(Strings.Chr(Strings.Asc(Strings.Mid(TheText, num2, 1)) + 2))
            text += str
            num2 += 1
        End While
        Return Strings.Trim(text)
    End Function

    Public Function SimpleDEncrypt(TheText As String) As String
        Dim text As String = ""
        Dim arg_12_0 As Integer = 1
        Dim num As Integer = Strings.Len(TheText)
        Dim num2 As Integer = arg_12_0
        ' The following expression was wrapped in a checked-statement
        While True
            Dim arg_48_0 As Integer = num2
            Dim num3 As Integer = num
            If arg_48_0 > num3 Then
                Exit While
            End If
            Dim str As String = Conversions.ToString(Strings.Chr(Strings.Asc(Strings.Mid(TheText, num2, 1)) - 2))
            text += str
            num2 += 1
        End While
        Return Strings.Trim(text)
    End Function

    Public Function CM(s As String) As String
        Dim arg_0B_0 As Long = 1L
        Dim num As Long = CLng(Strings.Len(s))
        Dim num2 As Long = arg_0B_0
        ' The following expression was wrapped in a checked-statement
        Dim text As String
        While True
            Dim arg_3D_0 As Long = num2
            Dim num3 As Long = num
            If arg_3D_0 > num3 Then
                Exit While
            End If
            text += Conversions.ToString(Strings.Chr(Strings.Asc(Strings.Mid(s, CInt(num2), 1)) Xor 255))
            num2 += 1L
        End While
        Return text
    End Function
    Public Function CreateRandomSalt() As String
        'the following is the string that will hold the salt charachters
        Dim mix As String = TextBox40.Text
        Dim salt As String = ""
        Dim rnd As New Random
        Dim sb As New StringBuilder
        For i As Integer = 1 To 100 'Length of the salt
            Dim x As Integer = rnd.Next(0, mix.Length - 1)
            salt &= (mix.Substring(x, 1))
        Next
        Return salt
    End Function
    Public Function Hash512(password As String, salt As String) As String
        Dim convertedToBytes As Byte() = Encoding.UTF8.GetBytes(password & salt)
        Dim hashType As HashAlgorithm = New SHA512Managed()
        Dim hashBytes As Byte() = hashType.ComputeHash(convertedToBytes)
        Dim hashedResult As String = Convert.ToBase64String(hashBytes)
        Return hashedResult
    End Function
#End Region

#Region "MD5"
    Public Shared Function Md5Encrypt(bytData As Byte(), sKey As String, Optional tMode As CipherMode = CipherMode.ECB, Optional tPadding As PaddingMode = PaddingMode.PKCS7) As Byte()
        Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
        Dim key As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(sKey))
        mD5CryptoServiceProvider.Clear()
        Dim tripleDESCryptoServiceProvider As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider() With {.Key = key, .Mode = tMode, .Padding = tPadding}
        Dim result As Byte() = tripleDESCryptoServiceProvider.CreateEncryptor().TransformFinalBlock(bytData, 0, bytData.Length)
        tripleDESCryptoServiceProvider.Clear()
        Return result
    End Function
    Public Function MD5Decrypt(ByVal bytData As Byte(), ByVal sKey As String, Optional ByVal tMode As CipherMode = 2, Optional ByVal tPadding As PaddingMode = 2) As Byte()
        Dim provider As New MD5CryptoServiceProvider
        Dim buffer2 As Byte() = provider.ComputeHash(Encoding.UTF8.GetBytes(sKey))
        provider.Clear()
        Dim provider2 As New TripleDESCryptoServiceProvider
        provider2.Key = buffer2
        provider2.Mode = tMode
        provider2.Padding = tPadding
        Dim buffer3 As Byte() = provider2.CreateDecryptor.TransformFinalBlock(bytData, 0, bytData.Length)
        provider2.Clear()
        Return buffer3
    End Function
#End Region
#Region "Compression(GZip)"
    Public Shared Function Zip_G(ByVal text As String) As String
        Dim buffer As Byte() = Encoding.Unicode.GetBytes(text)
        Dim ms As New MemoryStream()
        Using zip__1 As New GZipStream(ms, CompressionMode.Compress, True)
            zip__1.Write(buffer, 0, buffer.Length)
        End Using
        ms.Position = 0
        Dim outStream As New MemoryStream()
        Dim compressed As Byte() = New Byte(ms.Length - 1) {}
        ms.Read(compressed, 0, compressed.Length)
        Dim gzBuffer As Byte() = New Byte(compressed.Length + 3) {}
        System.Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length)
        System.Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4)
        Return Convert.ToBase64String(gzBuffer)
    End Function
    Public Shared Function UnZip_G(ByVal compressedText As String) As String
        Dim gzBuffer As Byte() = Convert.FromBase64String(compressedText)
        Using ms As New MemoryStream()
            Dim msgLength As Integer = BitConverter.ToInt32(gzBuffer, 0)
            ms.Write(gzBuffer, 4, gzBuffer.Length - 4)
            Dim buffer As Byte() = New Byte(msgLength - 1) {}
            ms.Position = 0
            Using zip As New GZipStream(ms, CompressionMode.Decompress)
                zip.Read(buffer, 0, buffer.Length)
            End Using
            Return Encoding.Unicode.GetString(buffer, 0, buffer.Length)
        End Using
    End Function
    Public Shared Function GZip(byte_0 As Byte()) As Byte()
        Dim memoryStream As MemoryStream = New MemoryStream()
        Try
            Dim gZipStream As GZipStream = New GZipStream(memoryStream, CompressionMode.Compress)
            Try
                gZipStream.Write(byte_0, 0, byte_0.Length)
                gZipStream.Close()
                byte_0 = New Byte(memoryStream.ToArray().Length - 1 + 1 - 1 + 1 - 1 + 1 - 1) {}
                byte_0 = memoryStream.ToArray()
            Finally
                Dim flag As Boolean = gZipStream IsNot Nothing
                If flag Then
                    CType(gZipStream, IDisposable).Dispose()
                End If
            End Try
            memoryStream.Close()
        Finally
            Dim flag As Boolean = memoryStream IsNot Nothing
            If flag Then
                CType(memoryStream, IDisposable).Dispose()
            End If
        End Try
        Return byte_0
    End Function
#End Region
#Region "Compression(Deflate)"
    Public Shared Function Zip_deflate(ByVal text As String) As String
        Dim buffer As Byte() = Encoding.Unicode.GetBytes(text)
        Dim ms As New MemoryStream()
        Using zip__1 As New DeflateStream(ms, CompressionMode.Compress, True)
            zip__1.Write(buffer, 0, buffer.Length)
        End Using
        ms.Position = 0
        Dim outStream As New MemoryStream()
        Dim compressed As Byte() = New Byte(ms.Length - 1) {}
        ms.Read(compressed, 0, compressed.Length)
        Dim gzBuffer As Byte() = New Byte(compressed.Length + 3) {}
        System.Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length)
        System.Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4)
        Return Convert.ToBase64String(gzBuffer)
    End Function
    Public Shared Function UnZip_deflate(ByVal compressedText As String) As String
        Dim gzBuffer As Byte() = Convert.FromBase64String(compressedText)
        Using ms As New MemoryStream()
            Dim msgLength As Integer = BitConverter.ToInt32(gzBuffer, 0)
            ms.Write(gzBuffer, 4, gzBuffer.Length - 4)
            Dim buffer As Byte() = New Byte(msgLength - 1) {}
            ms.Position = 0
            Using zip As New DeflateStream(ms, CompressionMode.Decompress)
                zip.Read(buffer, 0, buffer.Length)
            End Using
            Return Encoding.Unicode.GetString(buffer, 0, buffer.Length)
        End Using
    End Function
#End Region
#Region "~Draven's Algorithm"
    Function DecryptString_1(ByVal Text As String) As String
        Dim DecryptedString As String
        Dim CharFound As Integer
        Dim DecryptedChar As Integer
        DecryptedString = ""
        For N = 1 To Len(Text)
            CharFound = SearchChar(Mid(Text, N, 1))
            If CharFound >= 20 Then
                DecryptedChar = CharFound - 20
            Else
                DecryptedChar = CharFound + 236
            End If
            DecryptedString = DecryptedString & Chr(DecryptedChar)
        Next N
        Return DecryptedString
    End Function
    Function CryptString_1(ByVal Text As String) As String
        Dim CryptedString As String
        Dim CharFound As Integer
        Dim CryptedChar As Integer
        CryptedString = ""
        For N = 1 To Len(Text)
            CharFound = SearchChar(Mid(Text, N, 1))
            If CharFound <= 235 Then
                CryptedChar = CharFound + 20
            Else
                CryptedChar = CharFound - 236
            End If
            CryptedString = CryptedString & Chr(CryptedChar)
        Next N
        Return CryptedString
    End Function
#End Region
#Region "CustomLine"
    Private Shared Function converttoline(ByVal text_to_convert As String) As String
        Dim str2 As String = text_to_convert
        If str2.Contains("|") Then
            Return str2.Replace(" || ", "0").Replace(" | ", "1")
        End If
        Return str2.Replace("0", " || ").Replace("1", " | ")
    End Function
    Public Shared Function Decrypt_CustomLine(ByVal Text_to_Decrypt As String) As String
        Dim str2 As String = Text_to_Decrypt
        str2 = converttoline(str2)
        Dim str As String = Regex.Replace(str2, "[^01]", "")
        Dim bytes As Byte() = New Byte((CInt(Math.Round((str.Length / 8) - 1)) + 1) - 1) {}
        Dim num2 As Integer = (bytes.Length - 1)
        Dim i As Integer = 0
        Do While (i <= num2)
            bytes(i) = Convert.ToByte(str.Substring((i * 8), 8), 2)
            i += 1
        Loop
        Return Encoding.ASCII.GetString(bytes)
    End Function
    Public Shared Function Encrypt_CustomLine(ByVal text_to_Encrypt As String) As String
        Dim str2 As String = text_to_Encrypt
        Dim builder As New StringBuilder
        Dim num As Byte
        For Each num In Encoding.ASCII.GetBytes(text_to_Encrypt)
            builder.Append(Convert.ToString(num, 2).PadLeft(8, "0"c))
            builder.Append(" ")
        Next
        Return converttoline(builder.ToString.Substring(0, (builder.ToString.Length - 1)))
    End Function
#End Region
#Region "Binary"
    Private Function ConvertToBinary(ByVal str As String) As String
        Dim converted As New StringBuilder
        For Each b As Byte In Encoding.ASCII.GetBytes(str)
            converted.Append(Convert.ToString(b, 2).PadLeft(8, "0"))
        Next
        Return converted.ToString()
    End Function
    Private Function ConvertToAscii(ByVal str As String) As String
        Dim chars As String = Regex.Replace(str, "[^01]", "")
        Dim arr((chars.Length / 8) - 1) As Byte
        For i As Integer = 0 To arr.Length - 1
            arr(i) = Convert.ToByte(chars.Substring(i * 8, 8), 2)
        Next
        Return Encoding.ASCII.GetString(arr)
    End Function
#End Region
#Region "HEX"
    Public Function String2Hex(ByVal input As String) As String
        Dim out As New StringBuilder
        For Each c As String In input
            Dim temp As String = Hex(Asc(c))
            out.Append(temp & " ")
        Next
        Return out.ToString.Substring(0, out.Length - 1)
    End Function
    Public Function Hex2String(ByVal input As String) As String
        Dim out As New StringBuilder
        Dim data As String() = Split(input, " ")
        For Each s As String In data
            out.Append(Chr("&H" & s))
        Next
        Return out.ToString
    End Function
#End Region
#Region "pr0t3"
    Public Function pr0t3_encrypt(ByVal message As String)
        Dim encrypted As String
        Dim key As Integer = NumericUpDown43.Value
        message = StrReverse(message)
        For Each c As Char In message
            encrypted += Chr((Asc(c) + key))
        Next
        Return encrypted
    End Function
    Public Function pr0t3_decrypt(ByVal message As String)
        Dim decrypted As String
        Dim key As Integer = NumericUpDown43.Value
        For Each c As Char In message
            decrypted = decrypted & Chr((Asc(c) - key))
        Next
        decrypted = StrReverse(decrypted)
        Return decrypted
    End Function
#End Region
#Region "AES"
    Public Function AES_Encrypt(ByVal input As String, ByVal pass As String) As String
        Dim AES As New RijndaelManaged
        Dim Hash_AES As New MD5CryptoServiceProvider
        Dim encrypted As String = ""
        Try
            Dim hash(NumericUpDown44.Value) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESEncrypter As ICryptoTransform = AES.CreateEncryptor

            Dim Buffer As Byte() = Encoding.ASCII.GetBytes(input)
            encrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return encrypted
        Catch ex As Exception
        End Try
    End Function
    Public Function AES_Decrypt(ByVal input As String, ByVal pass As String) As String
        Dim AES As New RijndaelManaged
        Dim Hash_AES As New MD5CryptoServiceProvider
        Dim decrypted As String = ""
        Try
            Dim hash(NumericUpDown44.Value) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESDecrypter As ICryptoTransform = AES.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(input)
            decrypted = Encoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return decrypted
        Catch ex As Exception
        End Try
    End Function
#End Region
#Region "DES"
    Public Function DES_Encrypt(ByVal input As String, ByVal pass As String) As String
        Dim DES As New DESCryptoServiceProvider
        Dim Hash_DES As New MD5CryptoServiceProvider
        Dim encrypted As String = ""
        Try
            Dim hash(NumericUpDown45.Value) As Byte
            Dim temp As Byte() = Hash_DES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 8)
            DES.Key = hash
            DES.Mode = CipherMode.ECB
            Dim DESEncrypter As ICryptoTransform = DES.CreateEncryptor
            Dim Buffer As Byte() = Encoding.ASCII.GetBytes(input)
            encrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return encrypted
        Catch ex As Exception
        End Try
    End Function
    Public Function DES_Decrypt(ByVal input As String, ByVal pass As String) As String
        Dim DES As New DESCryptoServiceProvider
        Dim Hash_DES As New MD5CryptoServiceProvider
        Dim decrypted As String = ""
        Try
            Dim hash(NumericUpDown45.Value) As Byte
            Dim temp As Byte() = Hash_DES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 8)
            DES.Key = hash
            DES.Mode = CipherMode.ECB
            Dim DESDecrypter As ICryptoTransform = DES.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(input)
            decrypted = Encoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return decrypted
        Catch ex As Exception
        End Try
    End Function
#End Region
#Region "CustomXOR"
    Public Function CustomXOR_Encrypt(ByVal Input As String, ByVal pass As String) As String
        Dim out As New StringBuilder
        Dim Hash As New MD5CryptoServiceProvider
        Dim XorHash As Byte() = Hash.ComputeHash(Encoding.ASCII.GetBytes(pass))
        Dim u As Integer
        For i As Integer = 0 To Input.Length - 1
            Dim tmp As String = Hex(Asc(Input(i)) Xor XorHash(u))
            If tmp.Length = 1 Then tmp = "0" & tmp
            out.Append(tmp)
            If u = pass.Length - 1 Then u = 0 Else u = u + 1
        Next
        Return out.ToString
    End Function
    Public Function CustomXOR_Decrypt(ByVal Input As String, ByVal pass As String) As String
        Dim out As New StringBuilder
        Dim Hash As New MD5CryptoServiceProvider
        Dim XorHash As Byte() = Hash.ComputeHash(Encoding.ASCII.GetBytes(pass))
        Dim u As Integer
        For i As Integer = 0 To Input.Length - 1 Step +2
            Dim tmp As String = Chr(("&H" & Input.Substring(i, 2)) Xor XorHash(u))
            out.Append(tmp)
            If u = pass.Length - 1 Then u = 0 Else u = u + 1
        Next
        Return out.ToString
    End Function
#End Region
#Region "XOR"
    Public Function XOR_Encrypt(ByVal Input As String, ByVal pass As String) As String
        Dim out As New StringBuilder
        Dim u As Integer
        For i As Integer = 0 To Input.Length - 1
            Dim tmp As String = Hex(Asc(Input(i)) Xor Asc(pass(u)))
            If tmp.Length = 1 Then tmp = "0" & tmp
            out.Append(tmp)
            If u = pass.Length - 1 Then u = 0 Else u = u + 1
        Next
        Return out.ToString
    End Function
    Public Function XOR_Decrypt(ByVal Input As String, ByVal pass As String) As String
        Dim out As New StringBuilder
        Dim u As Integer
        For i As Integer = 0 To Input.Length - 1 Step +2
            Dim tmp As String = Chr(("&H" & Input.Substring(i, 2)) Xor Asc(pass(u)))
            out.Append(tmp)
            If u = pass.Length - 1 Then u = 0 Else u = u + 1
        Next
        Return out.ToString
    End Function
#End Region
#Region "RSA"
    Public Function RSA_Encrypt(ByVal Input As String) As String
        Dim cp As New CspParameters
        cp.Flags = CspProviderFlags.UseMachineKeyStore
        cp.KeyContainerName = "Keys"
        Dim RSA As New RSACryptoServiceProvider(cp)

        Dim buffer As Byte() = Encoding.UTF8.GetBytes(Input)
        Dim encrypted As Byte() = RSA.Encrypt(buffer, True)
        Return Convert.ToBase64String(encrypted)
    End Function
    Public Function RSA_Decrypt(ByVal Input As String) As String
        Dim cp As New CspParameters
        cp.Flags = CspProviderFlags.UseMachineKeyStore
        cp.KeyContainerName = "Keys"
        Dim RSA As New RSACryptoServiceProvider(cp)
        Dim buffer As Byte() = Convert.FromBase64String(Input)
        Dim decrypted As Byte() = RSA.Decrypt(buffer, True)
        Return Encoding.UTF8.GetString(decrypted)
    End Function
#End Region
#Region "Rot13"
    Public Function Rot13(ByVal value As String) As String
        Dim lowerA As Integer = Asc("a"c)
        Dim lowerZ As Integer = Asc("z"c)
        Dim lowerM As Integer = Asc("m"c)
        Dim upperA As Integer = Asc("A"c)
        Dim upperZ As Integer = Asc("Z"c)
        Dim upperM As Integer = Asc("M"c)
        Dim array As Char() = value.ToCharArray
        Dim i As Integer
        For i = 0 To array.Length - 1
            Dim number As Integer = Asc(array(i))
            If ((number >= lowerA) AndAlso (number <= lowerZ)) Then
                If (number > lowerM) Then
                    number -= 13
                Else
                    number += 13
                End If
            ElseIf ((number >= upperA) AndAlso (number <= upperZ)) Then
                If (number > upperM) Then
                    number -= 13
                Else
                    number += 13
                End If
            End If
            array(i) = Chr(number)
        Next i
        Return New String(array)
    End Function
#End Region
#Region "Caesar Cipher"
    Public Function c_Encrypt(ByVal PlainText As String, ByVal Key As Integer) As String
        Dim PlainChar() As Char = PlainText.ToCharArray()
        Dim Ascii(PlainChar.Length) As Integer
        For Count As Integer = 0 To PlainChar.Length - 1
            Ascii(Count) = Asc(PlainChar(Count))
            If Ascii(Count) >= 65 And Ascii(Count) <= 90 Then
                Ascii(Count) = ((Ascii(Count) - 65 + Key) Mod 26) + 65
            ElseIf Ascii(Count) >= 97 And Ascii(Count) <= 122 Then
                Ascii(Count) = ((Ascii(Count) - 97 + Key) Mod 26) + 97
            End If
            PlainChar(Count) = Chr(Ascii(Count))
        Next
        Return PlainChar
    End Function
    Public Function c_Decrypt(ByVal CipherText As String, ByVal Key As Integer) As String
        Dim CipherChar() As Char = CipherText.ToCharArray()
        Dim Ascii(CipherChar.Length) As Integer
        For Count As Integer = 0 To CipherChar.Length - 1
            Ascii(Count) = Asc(CipherChar(Count))
            If Ascii(Count) >= 65 And Ascii(Count) <= 90 Then
                Ascii(Count) = ((Ascii(Count) - 65 - (Key Mod 26) + 26)) Mod 26 + 65
            ElseIf Ascii(Count) >= 97 And Ascii(Count) <= 122 Then
                Ascii(Count) = (((Ascii(Count) - 97 - (Key Mod 26) + 26)) Mod 26) + 97
            End If
            CipherChar(Count) = Chr(Ascii(Count))
        Next
        Return CipherChar
    End Function
#End Region
#Region "Hashes"








    Public Function RIPEMD160Hash(ByVal input As String) As String
        Dim RIPEMD160 As New RIPEMD160Managed
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = RIPEMD160.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function SHA1Hash(ByVal input As String) As String
        Dim SHA1 As New SHA1CryptoServiceProvider
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = SHA1.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function SHA256Hash(ByVal input As String) As String
        Dim SHA256 As New SHA256Managed
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = SHA256.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function SHA348Hash(ByVal input As String) As String
        Dim SHA348 As New SHA384Managed
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = SHA348.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function SHA512Hash(ByVal input As String) As String
        Dim SHA512 As New SHA512Managed
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = SHA512.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function MD5Hash(ByVal input As String) As String
        Dim MD5 As New MD5CryptoServiceProvider
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACMD5(ByVal input As String) As String
        Dim MD5 As New HMACMD5
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACRIPEMD160(ByVal input As String) As String
        Dim MD5 As New HMACRIPEMD160
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACSHA1(ByVal input As String) As String
        Dim MD5 As New HMACSHA1
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACSHA256(ByVal input As String) As String
        Dim MD5 As New HMACSHA256
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACSHA384(ByVal input As String) As String
        Dim MD5 As New HMACSHA384
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function HMACSHA512(ByVal input As String) As String
        Dim MD5 As New HMACSHA512
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function MACTripleDES(ByVal input As String) As String
        Dim MD5 As New MACTripleDES
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.ComputeHash(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function

#End Region
    Public Function DSA(ByVal input As String) As String
        Dim MD5 As New DSACryptoServiceProvider
        Dim Data As Byte()
        Dim Result As Byte()
        Dim Res As String = ""
        Dim Tmp As String = ""
        Data = Encoding.ASCII.GetBytes(input)
        Result = MD5.SignData(Data)
        For i As Integer = 0 To Result.Length - 1
            Tmp = Hex(Result(i))
            If Len(Tmp) = 1 Then Tmp = "0" & Tmp
            Res += Tmp
        Next
        Return Res
    End Function
    Public Function hash_sha256(ByVal text_hash As String) As String
        'On déclare la variable servant à crypter
        Dim sha256 As New SHA256Managed
        Dim TexteEnBit() As Byte
        Dim TexteHache() As Byte = Nothing

        ' Récupération de la valeur en bit du texte à hacher
        TexteEnBit = System.Text.Encoding.UTF8.GetBytes(text_hash)

        ' Hachage
        TexteHache = sha256.ComputeHash(TexteEnBit)
        'Libération des ressources
        sha256.Clear()

        ' Renvoi
        hash_sha256 = ByteArrayToString(TexteHache)
    End Function
    Function ByteArrayToString(ByVal arrInput() As Byte) As String
        Dim i As Integer
        Dim sOutput As New StringBuilder(arrInput.Length)
        For i = 0 To arrInput.Length - 1
            sOutput.Append(arrInput(i).ToString("X2"))
        Next
        Return sOutput.ToString().ToLower
    End Function
#Region "Vigenere"
    Public Function VeginereDecrypt(ByVal proj As String, ByVal key As String)
        Dim decryptedText As String = ""
        For i As Integer = 1 To proj.Length
            Dim temp As Integer = AscW(GetChar(proj, i)) - AscW(GetChar(key, i Mod key.Length + 1))
            decryptedText += ChrW(temp)
        Next
        Return decryptedText
    End Function
#End Region
#Region "BASE64"
    Public Function BASE64_Encode(ByVal input As String) As String
        Return Convert.ToBase64String(Encoding.ASCII.GetBytes(input))
    End Function
    Public Function BASE64_Decode(ByVal input As String) As String
        Return Encoding.ASCII.GetString(Convert.FromBase64String(input))
    End Function
#End Region
#Region "MEGAN35"
    Public Function MEGAN35_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox14.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function MEGAN35_Decode(ByVal input As String) As String
        Dim key As String = TextBox15.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "ZONG22"
    Public Function ZONG22_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox17.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function ZONG22_Decode(ByVal input As String) As String
        Dim key As String = TextBox16.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "TRIPO5"
    Public Function TRIPO5_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox20.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function TRIPO5_Decode(ByVal input As String) As String
        Dim key As String = TextBox18.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "Vernam"
    Public Function Vernam(ByVal system As String, ByVal key As String) As String
        Dim i, isystem, ikey As Integer
        For i = 1 To Len(key)
            ikey = ikey + AscW(Mid(key, i, 1))
        Next i
        For i = 1 To Len(system)
            isystem = AscW(Mid(system, i, 1)) - ikey Mod 5555
            Vernam = Vernam & ChrW(isystem)
        Next i

    End Function
#End Region
#Region "TIGO3FX"
    Public Function TIGO3FX_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox23.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function TIGO3FX_Decode(ByVal input As String) As String
        Dim key As String = TextBox22.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "FERON74"
    Public Function FERON74_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox25.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function FERON74_Decode(ByVal input As String) As String
        Dim key As String = TextBox24.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "ESAB46"
    Public Function ESAB46_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox27.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function ESAB46_Decode(ByVal input As String) As String
        Dim key As String = TextBox26.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "GILA7"
    Public Function GILA7_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox28.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function GILA7_Decode(ByVal input As String) As String
        Dim key As String = TextBox29.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "HAZZ15"
    Public Function HAZZ15_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox30.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function HAZZ15_Decode(ByVal input As String) As String
        Dim key As String = TextBox31.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "Atom128"
    Public Function Atom128_Encode(ByVal input As String) As String
        input = Uri.EscapeDataString(input)
        Dim key As String = TextBox32.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs As Integer() = {0, 0, 0}
            For b As Integer = 0 To 2
                If i < input.Length Then chrs(b) = Asc(input(i))
                i += 1
            Next
            enc(0) = chrs(0) >> 2
            enc(1) = ((chrs(0) And 3) << 4) Or (chrs(1) >> 4)
            enc(2) = ((chrs(1) And 15) << 2) Or (chrs(2) >> 6)
            enc(3) = chrs(2) And 63
            If chrs(1) = 0 Then
                enc(2) = 64
                enc(3) = 64
            End If
            If chrs(2) = 0 Then
                enc(3) = 64
            End If
            For Each x As Integer In enc
                out.Append(key(x))
            Next
        Loop While i < input.Length
        Return out.ToString
    End Function
    Public Function Atom128_Decode(ByVal input As String) As String
        Dim key As String = TextBox33.Text
        Dim out As New StringBuilder
        Dim i As Integer
        Do
            Dim enc(3) As Integer
            Dim chrs() As Integer = {0, 0, 0}
            For b As Integer = 0 To 3
                enc(b) = key.IndexOf(input(i))
                i = i + 1
            Next
            chrs(0) = (enc(0) << 2) Or (enc(1) >> 4)
            chrs(1) = (enc(1) And 15) << 4 Or (enc(2) >> 2)
            chrs(2) = (enc(2) And 3) << 6 Or enc(3)
            out.Append(Chr(chrs(0)))
            If enc(2) <> 64 Then out.Append(Chr(chrs(1)))
            If enc(3) <> 64 Then out.Append(Chr(chrs(2)))
        Loop While i < input.Length
        Return out.ToString
    End Function
#End Region
#Region "RC2"
    Public Function RC2Encrypt(ByVal strInput As String, ByVal strPassword As String) As String
        Dim RC2 As New RC2CryptoServiceProvider
        Dim HashRC2 As New MD5CryptoServiceProvider
        Dim strEncrypted As String = ""
        Try
            Dim Hash() As Byte = HashRC2.ComputeHash(Encoding.ASCII.GetBytes(strPassword))

            RC2.Key = Hash
            RC2.Mode = CipherMode.ECB
            Dim DESEncrypter As ICryptoTransform = RC2.CreateEncryptor
            Dim Buffer As Byte() = Encoding.ASCII.GetBytes(strInput)
            strEncrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return strEncrypted
        Catch ex As Exception
        End Try
    End Function
    Public Function RC2Decrypt(ByVal strInput As String, ByVal strPassword As String) As String
        Dim RC2 As New RC2CryptoServiceProvider
        Dim HashRC2 As New MD5CryptoServiceProvider
        Dim strDecrypted As String = ""
        Try
            Dim Hash() As Byte = HashRC2.ComputeHash(Encoding.ASCII.GetBytes(strPassword))
            RC2.Key = Hash
            RC2.Mode = CipherMode.ECB
            Dim DESDecrypter As ICryptoTransform = RC2.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(strInput)
            strDecrypted = Encoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return strDecrypted
        Catch ex As Exception
        End Try
    End Function
#End Region
#Region "Atbash Cipher"
    Function Atbash_Cipher(ByVal input As String)
        Dim result As String = ""
        For Each x As Char In input
            If Char.IsLower(x) Then
                Dim diff As Integer = Asc(x) - Asc("a")
                result += Chr(Asc("z") - diff)
            ElseIf Char.IsUpper(x) Then
                Dim diff As Integer = Asc(x) - Asc("A")
                result += Chr(Asc("Z") - diff)
            Else
                result += x
            End If
        Next
        Return result
    End Function
#End Region
#Region "RC4"
    Public Shared Function rc4(ByVal message As String, ByVal password As String) As String
        Dim i As Integer = 0
        Dim j As Integer = 0
        Dim cipher As New StringBuilder
        Dim returnCipher As String = String.Empty
        Dim sbox As Integer() = New Integer(256) {}
        Dim key As Integer() = New Integer(256) {}
        Dim intLength As Integer = password.Length
        Dim a As Integer = 0
        While a <= 255
            Dim ctmp As Char = (password.Substring((a Mod intLength), 1).ToCharArray()(0))
            key(a) = Asc(ctmp)
            sbox(a) = a
            System.Math.Max(System.Threading.Interlocked.Increment(a), a - 1)
        End While
        Dim x As Integer = 0
        Dim b As Integer = 0
        While b <= 255
            x = (x + sbox(b) + key(b)) Mod 256
            Dim tempSwap As Integer = sbox(b)
            sbox(b) = sbox(x)
            sbox(x) = tempSwap
            System.Math.Max(System.Threading.Interlocked.Increment(b), b - 1)
        End While
        a = 1
        While a <= message.Length
            Dim itmp As Integer = 0
            i = (i + 1) Mod 256
            j = (j + sbox(i)) Mod 256
            itmp = sbox(i)
            sbox(i) = sbox(j)
            sbox(j) = itmp
            Dim k As Integer = sbox((sbox(i) + sbox(j)) Mod 256)
            Dim ctmp As Char = message.Substring(a - 1, 1).ToCharArray()(0)
            itmp = Asc(ctmp)
            Dim cipherby As Integer = itmp Xor k
            cipher.Append(Chr(cipherby))
            System.Math.Max(System.Threading.Interlocked.Increment(a), a - 1)
        End While
        returnCipher = cipher.ToString
        cipher.Length = 0
        Return returnCipher
    End Function
    Public Function RC4decrypt(ByVal D1 As Byte(), ByVal D2 As String) As Byte()
        Dim D3 As Byte() = System.Text.Encoding.ASCII.GetBytes(D2)
        Dim D4, D5, D6 As UInteger
        Dim D7 As UInteger() = New UInteger(255) {}
        Dim D8 As Byte() = New Byte(D1.Length - 1) {}
        For D4 = 0 To 255
            D7(D4) = D4
        Next
        For D4 = 0 To 255
            D5 = (D5 + D3(D4 Mod D3.Length) + D7(D4)) And 255
            D6 = D7(D4)
            D7(D4) = D7(D5)
            D7(D5) = D6
        Next
        D4 = 0 : D5 = 0
        For D9 = 0 To D8.Length - 1
            D4 = (D4 + 1) And 255
            D5 = (D5 + D7(D4)) And 255
            D6 = D7(D4)
            D7(D4) = D7(D5)
            D7(D5) = D6
            D8(D9) = D1(D9) Xor D7((D7(D4) + D7(D5)) And 255)
        Next
        Return D8
    End Function
#End Region
#Region "TripleDES"
    Public Function TripleDES_Encrypt(ByVal input As String, ByVal pass As String) As String
        Dim TripleDES As New TripleDESCryptoServiceProvider
        Dim Hash_TripleDES As New MD5CryptoServiceProvider
        Dim encrypted As String = ""
        Try
            Dim hash(NumericUpDown46.Value) As Byte
            Dim temp As Byte() = Hash_TripleDES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 8)
            TripleDES.Key = hash
            TripleDES.Mode = CipherMode.ECB
            Dim DESEncrypter As ICryptoTransform = TripleDES.CreateEncryptor
            Dim Buffer As Byte() = Encoding.ASCII.GetBytes(input)
            encrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return encrypted
        Catch ex As Exception
        End Try
    End Function
    Public Function TripleDES_Decrypt(ByVal input As String, ByVal pass As String) As String
        Dim TripleDES As New TripleDESCryptoServiceProvider
        Dim Hash_TripleDES As New MD5CryptoServiceProvider
        Dim decrypted As String = ""
        Try
            Dim hash(NumericUpDown46.Value) As Byte
            Dim temp As Byte() = Hash_TripleDES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 8)
            TripleDES.Key = hash
            TripleDES.Mode = CipherMode.ECB
            Dim DESDecrypter As ICryptoTransform = TripleDES.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(input)
            decrypted = Encoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return decrypted
        Catch ex As Exception
        End Try
    End Function
#End Region
#Region "Stairs"
    Public Shared Function Crypt(ByVal Data As String, ByVal key As String) As String
        Return Encoding.Default.GetString(Crypt(Encoding.Default.GetBytes(Data), Encoding.Default.GetBytes(key)))
    End Function
    Public Shared Function Crypt(ByVal Data() As Byte, ByVal key() As Byte) As Byte()
        For i = 0 To (Data.Length * 2) + key.Length
            Data(i Mod Data.Length) = CByte(CInt((Data(i Mod Data.Length)) + CInt(Data((i + 1) Mod Data.Length))) Mod 256) Xor key(i Mod key.Length)
        Next
        Return Data
    End Function
    Public Shared Function DeCrypt(ByVal Data As String, ByVal key As String) As String
        Return Encoding.Default.GetString(DeCrypt(Encoding.Default.GetBytes(Data), Encoding.Default.GetBytes(key)))
    End Function
    Public Shared Function DeCrypt(ByVal Data() As Byte, ByVal key() As Byte) As Byte()
        For i = (Data.Length * 2) + key.Length To 0 Step -1
            Data(i Mod Data.Length) = CByte((CInt(Data(i Mod Data.Length) Xor key(i Mod key.Length)) - CInt(Data((i + 1) Mod Data.Length)) + 256) Mod 256)
        Next
        Return Data
    End Function
#End Region
#Region "Polymorphic Stairs"
    Overloads Shared Function PolyCrypt(ByVal Data As String, ByVal Key As String, Optional ByVal ExtraRounds As UInteger = 0) As String
        Dim buff() As Byte = PolyCrypt(Encoding.Default.GetBytes(Data), Encoding.Default.GetBytes(Key), ExtraRounds)
        PolyCrypt = Encoding.Default.GetString(buff)
        Erase buff
    End Function
    Overloads Shared Function PolyCrypt(ByRef Data() As Byte, ByVal Key() As Byte, Optional ByVal ExtraRounds As UInteger = 0) As Byte()
        Array.Resize(Data, Data.Length + 1)
        Data(Data.Length - 1) = Convert.ToByte(New Random().Next(1, 255))
        For i = (Data.Length - 1) * (ExtraRounds + 1) To 0 Step -1
            Data(i Mod Data.Length) = CByte(CInt((Data(i Mod Data.Length)) + CInt(Data((i + 1) Mod Data.Length))) Mod 256) Xor Key(i Mod Key.Length)
        Next
        Return Data
    End Function
    Overloads Shared Function PolyDeCrypt(ByVal Data As String, ByVal Key As String, Optional ByVal ExtraRounds As UInteger = 0) As String
        Dim buff() As Byte = PolyDeCrypt(Encoding.Default.GetBytes(Data), Encoding.Default.GetBytes(Key), ExtraRounds)
        PolyDeCrypt = Encoding.Default.GetString(buff)
        Erase buff
    End Function
    Overloads Shared Function PolyDeCrypt(ByRef Data() As Byte, ByVal Key() As Byte, Optional ByVal ExtraRounds As UInteger = 0) As Byte()
        For i = 0 To (Data.Length - 1) * (ExtraRounds + 1)
            Data(i Mod Data.Length) = CByte((CInt(Data(i Mod Data.Length) Xor Key(i Mod Key.Length)) - CInt(Data((i + 1) Mod Data.Length)) + 256) Mod 256)
        Next
        Array.Resize(Data, Data.Length - 1)
        Return Data
    End Function
#End Region
#Region "Rijndael"
    Public Shared Function Rijndaelcrypt(ByVal File As String, ByVal Key As String)
        Dim oAesProvider As New RijndaelManaged
        Dim btClear() As Byte
        Dim btSalt() As Byte = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
        Dim oKeyGenerator As New Rfc2898DeriveBytes(Key, btSalt)
        oAesProvider.Key = oKeyGenerator.GetBytes(oAesProvider.Key.Length)
        oAesProvider.IV = oKeyGenerator.GetBytes(oAesProvider.IV.Length)
        Dim ms As New IO.MemoryStream
        Dim cs As New CryptoStream(ms,
          oAesProvider.CreateEncryptor(),
          CryptoStreamMode.Write)
        btClear = Encoding.UTF8.GetBytes(File)
        cs.Write(btClear, 0, btClear.Length)
        cs.Close()
        File = Convert.ToBase64String(ms.ToArray)
        Return File
    End Function
    Public Shared Function RijndaelDecrypt(ByVal UDecryptU As String, ByVal UKeyU As String)
        Dim XoAesProviderX As New RijndaelManaged
        Dim XbtCipherX() As Byte
        Dim XbtSaltX() As Byte = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
        Dim XoKeyGeneratorX As New Rfc2898DeriveBytes(UKeyU, XbtSaltX)
        XoAesProviderX.Key = XoKeyGeneratorX.GetBytes(XoAesProviderX.Key.Length)
        XoAesProviderX.IV = XoKeyGeneratorX.GetBytes(XoAesProviderX.IV.Length)
        Dim XmsX As New IO.MemoryStream
        Dim XcsX As New CryptoStream(XmsX, XoAesProviderX.CreateDecryptor(),
          CryptoStreamMode.Write)
        Try
            XbtCipherX = Convert.FromBase64String(UDecryptU)
            XcsX.Write(XbtCipherX, 0, XbtCipherX.Length)
            XcsX.Close()
            UDecryptU = Encoding.UTF8.GetString(XmsX.ToArray)
        Catch
        End Try
        Return UDecryptU
    End Function
#End Region
#Region "3DES"
    Public Shared Function EncryptString(ByVal Message As String, ByVal Passphrase As String) As String
        Dim Results() As Byte
        Dim UTF8 As UTF8Encoding = New UTF8Encoding
        Using HashProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim TDESKey() As Byte = HashProvider.ComputeHash(UTF8.GetBytes(Passphrase))
            Using TDESAlgorithm As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider() With {.Key = TDESKey, .Mode = CipherMode.ECB, .Padding = PaddingMode.PKCS7}
                Dim DataToEncrypt() As Byte = UTF8.GetBytes(Message)
                Try
                    Dim Encryptor As ICryptoTransform = TDESAlgorithm.CreateEncryptor
                    Results = Encryptor.TransformFinalBlock(DataToEncrypt, 0, DataToEncrypt.Length)
                Finally
                    TDESAlgorithm.Clear()
                    HashProvider.Clear()
                End Try
            End Using
        End Using
        Return Convert.ToBase64String(Results)
    End Function
    Public Shared Function DecryptString(ByVal Message As String, ByVal Passphrase As String) As String
        Dim Results() As Byte
        Dim UTF8 As UTF8Encoding = New UTF8Encoding
        Using HashProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim TDESKey() As Byte = HashProvider.ComputeHash(UTF8.GetBytes(Passphrase))
            Using TDESAlgorithm As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider() With {.Key = TDESKey, .Mode = CipherMode.ECB, .Padding = PaddingMode.PKCS7}
                Dim DataToDecrypt() As Byte = Convert.FromBase64String(Message)
                Try
                    Dim Decryptor As ICryptoTransform = TDESAlgorithm.CreateDecryptor
                    Results = Decryptor.TransformFinalBlock(DataToDecrypt, 0, DataToDecrypt.Length)
                Finally
                    TDESAlgorithm.Clear()
                    HashProvider.Clear()
                End Try
            End Using
        End Using
        Return UTF8.GetString(Results)
    End Function
#End Region
#Region "ZARA128"
    Public Function ZARA128_Encode(ByVal input As String) As String
        Dim out As New StringBuilder
        For Each c As Char In input
            Dim temp As Integer = Asc(c) + TextBoxX1.Text
            out.Append(temp.ToString & " ")
        Next
        Return out.ToString.Substring(0, out.Length - 1)
    End Function
    Public Function ZARA128_Decode(ByVal input As String) As String
        Dim out As New StringBuilder
        Dim data As String() = Split(input, " ")
        For Each s As String In data
            Dim temp As Integer = s - TextBoxX1.Text
            out.Append(Chr(temp))
        Next
        Return out.ToString
    End Function
#End Region
#Region "ARMON64"
    Public Function ARMON64_Encrypt(ByVal message As String, Optional ByVal key As String = "ARMON64-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 3 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)
        Dim x As Integer
        Do While x < message.Length
            Dim hextemp As String = ""
            Dim y As String = ""
            If x > 0 Then y = "+"
            For i As Integer = x To Math.Round(key.Length / 2)
                If i < message.Length Then hextemp += Hex(Asc(message(i)))
            Next
            Dim thenum As Double = "&H" & hextemp
            If Information.IsNumeric(thenum) = False Then Return message
            For z As Integer = 0 To key.Length - 1
                Dim operation As Integer = z Mod 4
                Select Case operation
                    Case 0
                        thenum += intkey(z)
                    Case 1
                        thenum /= intkey(z)
                    Case 2
                        thenum -= intkey(z)
                    Case 3
                        thenum *= 0.01 * intkey(z)
                End Select
            Next
            out.Append(y & thenum)
            x += Math.Round(key.Length / 2)
        Loop
        Return out.ToString.Replace(",", ".")
    End Function
    Public Function ARMON64_Decrypt(ByVal message As String, Optional ByVal key As String = "ARMON64-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 6 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)
        message = message.Replace(".", ",")
        Dim oOutString As String() = Split(message, "+")
        For x As Integer = 0 To oOutString.Length - 1
            For z As Integer = key.Length - 1 To 0 Step -1
                Dim operation As Integer = z Mod 4
                Select Case operation
                    Case 0
                        oOutString(x) -= intkey(z)
                    Case 1
                        oOutString(x) *= intkey(z)
                    Case 2
                        oOutString(x) += intkey(z)
                    Case 3
                        oOutString(x) /= 0.01 * intkey(z)
                End Select
            Next
            oOutString(x) = Hex(Math.Round(Double.Parse(oOutString(x))))
        Next
        For i As Integer = 0 To Join(oOutString).Length - 1 Step +2
            out.Append(Chr(("&H" & Join(oOutString).Substring(i, 2))))
        Next
        Return out.ToString
    End Function
#End Region
#Region "AER256"
    Public Function AER256_Encrypt(ByVal message As String, Optional ByVal key As String = "A256-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)
        Dim x As Integer
        Do While x < message.Length
            Dim hextemp As String = ""
            Dim y As String = ""
            If x > 0 Then y = ", "
            For i As Integer = x To Math.Round(key.Length / 2)
                If i < message.Length Then hextemp += Hex(Asc(message(i)))
            Next
            Dim thenum As Double = "&H" & hextemp
            If Information.IsNumeric(thenum) = False Then Return message
            For z As Integer = 0 To key.Length - 1
                Dim operation As Integer = z Mod 3
                Select Case operation
                    Case 0
                        thenum += intkey(z)
                    Case 1
                        thenum /= intkey(z)
                    Case 2
                        thenum -= intkey(z)
                    Case 3
                        thenum *= 0.02 * intkey(z)
                End Select
            Next
            Dim temp As String = thenum.ToString.Replace(",", ".")
            out.Append(y & temp)
            x += Math.Round(key.Length / 2)
        Loop
        Return out.ToString
    End Function
    Public Function AER256_Decrypt(ByVal message As String, Optional ByVal key As String = "A256-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)

        Dim oOutString As String() = Split(message, ", ")
        For i As Integer = 0 To oOutString.Length - 1
            oOutString(i) = oOutString(i).Replace(".", ",")
        Next
        For x As Integer = 0 To oOutString.Length - 1
            For z As Integer = key.Length - 1 To 0 Step -1
                Dim operation As Integer = z Mod 3
                Select Case operation
                    Case 0
                        oOutString(x) -= intkey(z)
                    Case 1
                        oOutString(x) *= intkey(z)
                    Case 2
                        oOutString(x) += intkey(z)
                    Case 3
                        oOutString(x) /= 0.02 * intkey(z)
                End Select
            Next
            oOutString(x) = Hex(Math.Round(Double.Parse(oOutString(x))))
        Next
        For i As Integer = 0 To Join(oOutString).Length - 1 Step +2
            out.Append(Chr(("&H" & Join(oOutString).Substring(i, 2))))
        Next
        Return out.ToString
    End Function
#End Region
#Region "EZIP64"
    Public Function EZIP64_Encrypt(ByVal message As String, Optional ByVal key As String = "EZIP64-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)
        Dim x As Integer
        Do While x < message.Length
            Dim hextemp As String = ""
            Dim y As String = ""
            If x > 0 Then y = "/"
            For i As Integer = x To Math.Round(key.Length / 3)
                If i < message.Length Then hextemp += Hex(Asc(message(i)))
            Next
            Dim thenum As Double = "&H" & hextemp
            If Information.IsNumeric(thenum) = False Then Return message
            For z As Integer = 0 To key.Length - 1
                Dim operation As Integer = z Mod 4
                Select Case operation
                    Case 0
                        thenum += intkey(z)
                    Case 1
                        thenum /= intkey(z)
                    Case 2
                        thenum -= intkey(z)
                    Case 3
                        thenum *= 0.02 * intkey(z)
                End Select
            Next
            Dim temp As String = thenum.ToString.Replace(",", ".")
            out.Append(y & temp)
            x += Math.Round(key.Length / 3)
        Loop
        Return out.ToString
    End Function
    Public Function EZIP64_Decrypt(ByVal message As String, Optional ByVal key As String = "EZIP64-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)

        Dim oOutString As String() = Split(message, "/")
        For i As Integer = 0 To oOutString.Length - 1
            oOutString(i) = oOutString(i).Replace(".", ",")
        Next
        For x As Integer = 0 To oOutString.Length - 1
            For z As Integer = key.Length - 1 To 0 Step -1
                Dim operation As Integer = z Mod 4
                Select Case operation
                    Case 0
                        oOutString(x) -= intkey(z)
                    Case 1
                        oOutString(x) *= intkey(z)
                    Case 2
                        oOutString(x) += intkey(z)
                    Case 3
                        oOutString(x) /= 0.02 * intkey(z)
                End Select
            Next
            oOutString(x) = Hex(Math.Round(Double.Parse(oOutString(x))))
        Next
        For i As Integer = 0 To Join(oOutString).Length - 1 Step +2
            out.Append(Chr(("&H" & Join(oOutString).Substring(i, 2))))
            Dim j As String = out.ToString
        Next
        Return out.ToString
    End Function
#End Region
#Region "OKTO3"
    Public Function OKTO3_Encrypt(ByVal message As String, Optional ByVal key As String = "PASS:OKTO3-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)
        Dim x As Integer
        Do While x < message.Length
            Dim hextemp As String = ""
            Dim y As String = ""
            If x > 0 Then y = ", "
            For i As Integer = x To Math.Round(key.Length / 6)
                If i < message.Length Then hextemp += Hex(Asc(message(i)))
            Next
            Dim thenum As Double = "&H" & hextemp
            If Information.IsNumeric(thenum) = False Then Return message
            For z As Integer = 0 To key.Length - 1
                Dim operation As Integer = z Mod 3
                Select Case operation
                    Case 0
                        thenum += intkey(z)
                    Case 1
                        thenum /= intkey(z)
                    Case 2
                        thenum -= intkey(z)
                    Case 3
                        thenum *= 500.005 * intkey(z)
                End Select
            Next
            Dim temp As String = thenum.ToString.Replace(",", ".")
            out.Append(y & temp)
            x += Math.Round(key.Length / 6)
        Loop
        Return out.ToString
    End Function
    Public Function OKTO3_Decrypt(ByVal message As String, Optional ByVal key As String = "PASS:OKTO3-CRYPO") As String
        Dim out As New System.Text.StringBuilder
        If key.Length < 10 Then Return message
        Dim intkey() As Byte = System.Text.Encoding.UTF8.GetBytes(key)

        Dim oOutString As String() = Split(message, ", ")
        For i As Integer = 0 To oOutString.Length - 1
            oOutString(i) = oOutString(i).Replace(".", ",")
        Next
        For x As Integer = 0 To oOutString.Length - 1
            For z As Integer = key.Length - 1 To 0 Step -1
                Dim operation As Integer = z Mod 3
                Select Case operation
                    Case 0
                        oOutString(x) -= intkey(z)
                    Case 1
                        oOutString(x) *= intkey(z)
                    Case 2
                        oOutString(x) += intkey(z)
                    Case 3
                        oOutString(x) /= 0.02 * intkey(z)
                End Select
            Next
            oOutString(x) = Hex(Math.Round(Double.Parse(oOutString(x))))
        Next
        For i As Integer = 0 To Join(oOutString).Length - 1 Step +2
            out.Append(Chr(("&H" & Join(oOutString).Substring(i, 2))))
        Next
        Return out.ToString
    End Function
#End Region
#Region "EnvY'S Encryption"
    Public Function EnvY_Encrypt(ByVal input As String, ByVal pass As String) As String
        Dim out As String
        input = Logintextbox1.Text
        out = AES_Encrypt(input, Key)
        out = RC2Encrypt(out, Key)
        out = XOR_Encrypt(out, Key)
        out = ESAB46_Encode(out)
        Return out.ToString
    End Function
    Public Function EnvY_Decrypt(ByVal input As String, ByVal pass As String) As String
        Dim out As String
        input = Logintextbox1.Text
        out = ESAB46_Decode(input)
        out = XOR_Decrypt(out, Key)
        out = RC2Decrypt(out, Key)
        out = AES_Decrypt(out, Key)
        Return out.ToString
    End Function
#End Region


#Region "NEW STUFF"
#Region "NEW HASHES"
#Region "SHA256"
    Private Shared Sub DBL_INT_ADD(ByRef a As UInteger, ByRef b As UInteger, c As UInteger)
        If a > &HFFFFFFFFUI - c Then
            b += 1
        End If
        a += c
    End Sub

    Private Shared Function ROTLEFT(a As UInteger, b As Byte) As UInteger
        Return ((a << b) Or (a >> (32 - b)))
    End Function

    Private Shared Function ROTRIGHT(a As UInteger, b As Byte) As UInteger
        Return (((a) >> (b)) Or ((a) << (32 - (b))))
    End Function

    Private Shared Function CH(x As UInteger, y As UInteger, z As UInteger) As UInteger
        Return (((x) And (y)) Xor (Not (x) And (z)))
    End Function

    Private Shared Function MAJ(x As UInteger, y As UInteger, z As UInteger) As UInteger
        Return (((x) And (y)) Xor ((x) And (z)) Xor ((y) And (z)))
    End Function

    Private Shared Function EP0(x As UInteger) As UInteger
        Return (ROTRIGHT(x, 2) Xor ROTRIGHT(x, 13) Xor ROTRIGHT(x, 22))
    End Function

    Private Shared Function EP1(x As UInteger) As UInteger
        Return (ROTRIGHT(x, 6) Xor ROTRIGHT(x, 11) Xor ROTRIGHT(x, 25))
    End Function

    Private Shared Function SIG0(x As UInteger) As UInteger
        Return (ROTRIGHT(x, 7) Xor ROTRIGHT(x, 18) Xor ((x) >> 3))
    End Function

    Private Shared Function SIG1(x As UInteger) As UInteger
        Return (ROTRIGHT(x, 17) Xor ROTRIGHT(x, 19) Xor ((x) >> 10))
    End Function

    Private Structure SHA256_CTX
        Public data As Byte()
        Public datalen As UInteger
        Public bitlen As UInteger()
        Public state As UInteger()
    End Structure

    Shared k As UInteger() = {&H428A2F98, &H71374491, &HB5C0FBCFUI, &HE9B5DBA5UI, &H3956C25B, &H59F111F1,
        &H923F82A4UI, &HAB1C5ED5UI, &HD807AA98UI, &H12835B01, &H243185BE, &H550C7DC3,
        &H72BE5D74, &H80DEB1FEUI, &H9BDC06A7UI, &HC19BF174UI, &HE49B69C1UI, &HEFBE4786UI,
        &HFC19DC6, &H240CA1CC, &H2DE92C6F, &H4A7484AA, &H5CB0A9DC, &H76F988DA,
        &H983E5152UI, &HA831C66DUI, &HB00327C8UI, &HBF597FC7UI, &HC6E00BF3UI, &HD5A79147UI,
        &H6CA6351, &H14292967, &H27B70A85, &H2E1B2138, &H4D2C6DFC, &H53380D13,
        &H650A7354, &H766A0ABB, &H81C2C92EUI, &H92722C85UI, &HA2BFE8A1UI, &HA81A664BUI,
        &HC24B8B70UI, &HC76C51A3UI, &HD192E819UI, &HD6990624UI, &HF40E3585UI, &H106AA070,
        &H19A4C116, &H1E376C08, &H2748774C, &H34B0BCB5, &H391C0CB3, &H4ED8AA4A,
        &H5B9CCA4F, &H682E6FF3, &H748F82EE, &H78A5636F, &H84C87814UI, &H8CC70208UI,
        &H90BEFFFAUI, &HA4506CEBUI, &HBEF9A3F7UI, &HC67178F2UI}

    Private Shared Sub SHA256Transform(ByRef ctx As SHA256_CTX, data As Byte())
        Dim a As UInteger, b As UInteger, c As UInteger, d As UInteger, e As UInteger, f As UInteger,
            g As UInteger, h As UInteger, i As UInteger, j As UInteger, t1 As UInteger, t2 As UInteger
        Dim m As UInteger() = New UInteger(63) {}

        i = 0
        j = 0
        While i < 16
            m(i) = ((CULng(data(j)) << 24) Or (CULng(data(j + 1)) << 16) Or (CULng(data(j + 2)) << 8) Or (data(j + 3))) And UInteger.MaxValue
            i += 1
            j += 4
        End While

        While i < 64
            m(i) = CULng(SIG1(m(i - 2))) + m(i - 7) + SIG0(m(i - 15)) + m(i - 16) And UInteger.MaxValue
            i += 1
        End While

        a = ctx.state(0)
        b = ctx.state(1)
        c = ctx.state(2)
        d = ctx.state(3)
        e = ctx.state(4)
        f = ctx.state(5)
        g = ctx.state(6)
        h = ctx.state(7)

        For i = 0 To 63
            t1 = (CULng(h) + EP1(e) + CH(e, f, g) + k(i) + m(i)) And UInteger.MaxValue
            t2 = (CULng(EP0(a)) + MAJ(a, b, c)) And UInteger.MaxValue
            h = g
            g = f
            f = e
            e = (CULng(d) + t1) And UInteger.MaxValue
            d = c
            c = b
            b = a
            a = (CULng(t1) + t2) And UInteger.MaxValue
        Next

        ctx.state(0) = (CULng(ctx.state(0)) + a) And UInteger.MaxValue
        ctx.state(1) = (CULng(ctx.state(1)) + b) And UInteger.MaxValue
        ctx.state(2) = (CULng(ctx.state(2)) + c) And UInteger.MaxValue
        ctx.state(3) = (CULng(ctx.state(3)) + d) And UInteger.MaxValue
        ctx.state(4) = (CULng(ctx.state(4)) + e) And UInteger.MaxValue
        ctx.state(5) = (CULng(ctx.state(5)) + f) And UInteger.MaxValue
        ctx.state(6) = (CULng(ctx.state(6)) + g) And UInteger.MaxValue
        ctx.state(7) = (CULng(ctx.state(7)) + h) And UInteger.MaxValue
    End Sub

    Private Shared Sub SHA256Init(ByRef ctx As SHA256_CTX)
        ctx.datalen = 0
        ctx.bitlen(0) = 0
        ctx.bitlen(1) = 0
        ctx.state(0) = &H6A09E667
        ctx.state(1) = &HBB67AE85UI
        ctx.state(2) = &H3C6EF372
        ctx.state(3) = &HA54FF53AUI
        ctx.state(4) = &H510E527F
        ctx.state(5) = &H9B05688CUI
        ctx.state(6) = &H1F83D9AB
        ctx.state(7) = &H5BE0CD19
    End Sub

    Private Shared Sub SHA256Update(ByRef ctx As SHA256_CTX, data As Byte(), len As UInteger)
        For i As UInteger = 0 To len - 1
            ctx.data(ctx.datalen) = data(i)
            ctx.datalen += 1

            If ctx.datalen = 64 Then
                SHA256Transform(ctx, ctx.data)
                DBL_INT_ADD(ctx.bitlen(0), ctx.bitlen(1), 512)
                ctx.datalen = 0
            End If
        Next
    End Sub

    Private Shared Sub SHA256Final(ByRef ctx As SHA256_CTX, hash As Byte())
        Dim i As UInteger = ctx.datalen

        If ctx.datalen < 56 Then
            ctx.data(System.Math.Max(i, i - 1)) = &H80
            i += 1

            While i < 56
                ctx.data(System.Math.Max(i, i - 1)) = &H0
                i += 1
            End While
        Else
            ctx.data(System.Math.Max(i, i - 1)) = &H80
            i += 1

            While i < 64
                ctx.data(System.Math.Max(i, i - 1)) = &H0
                i += 1
            End While

            SHA256Transform(ctx, ctx.data)
        End If

        DBL_INT_ADD(ctx.bitlen(0), ctx.bitlen(1), ctx.datalen * 8)
        ctx.data(63) = CByte(ctx.bitlen(0))
        ctx.data(62) = CByte(ctx.bitlen(0) >> 8)
        ctx.data(61) = CByte(ctx.bitlen(0) >> 16)
        ctx.data(60) = CByte(ctx.bitlen(0) >> 24)
        ctx.data(59) = CByte(ctx.bitlen(1))
        ctx.data(58) = CByte(ctx.bitlen(1) >> 8)
        ctx.data(57) = CByte(ctx.bitlen(1) >> 16)
        ctx.data(56) = CByte(ctx.bitlen(1) >> 24)
        SHA256Transform(ctx, ctx.data)

        For i = 0 To 3
            hash(i) = CByte(((ctx.state(0)) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 4) = CByte(((ctx.state(1)) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 8) = CByte(((ctx.state(2)) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 12) = CByte((ctx.state(3) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 16) = CByte((ctx.state(4) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 20) = CByte((ctx.state(5) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 24) = CByte((ctx.state(6) >> CInt(24 - i * 8)) And &HFF)
            hash(i + 28) = CByte((ctx.state(7) >> CInt(24 - i * 8)) And &HFF)
        Next
    End Sub

    Public Shared Function SHA256(data As String) As String
        Dim ctx As New SHA256_CTX()
        ctx.data = New Byte(63) {}
        ctx.bitlen = New UInteger(1) {}
        ctx.state = New UInteger(7) {}

        Dim hash As Byte() = New Byte(31) {}
        Dim hashStr As String = String.Empty

        SHA256Init(ctx)
        SHA256Update(ctx, Encoding.[Default].GetBytes(data), CUInt(data.Length))
        SHA256Final(ctx, hash)

        For i As Integer = 0 To 31
            hashStr += String.Format("{0:X2}", hash(i))
        Next

        Return hashStr
    End Function
#End Region
    Public Shared Function APHash(str As String) As UInteger
        Dim hash As ULong = &HAAAAAAAAUL
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = hash Xor If(((i And 1) = 0), (((hash << 7) Xor CByte(AscW(str(CInt(i)))) * (hash >> 3)) And UInteger.MaxValue), ((Not ((hash << 11) + (CByte(AscW(str(CInt(i)))) Xor (hash >> 5)))) And UInteger.MaxValue))
        Next

        Return hash
    End Function
    Public Shared Function BKDRHash(str As String) As UInteger
        Dim seed As UInteger = 131
        Dim hash As ULong = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = ((hash * seed) + CByte(AscW(str(CInt(i)))) And UInteger.MaxValue)
        Next

        Return hash
    End Function
    Public Shared Function BPHash(str As String) As UInteger
        Dim hash As UInteger = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = hash << 7 Xor CByte(AscW(str(CInt(i))))
        Next

        Return hash
    End Function
    Public Shared Function DEKHash(str As String) As UInteger
        Dim hash As UInteger = CUInt(str.Length)
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = ((hash << 5) Xor (hash >> 27)) Xor CByte(AscW(str(CInt(i))))
        Next

        Return hash
    End Function
    Public Shared Function DJBHash(str As String) As UInteger
        Dim hash As ULong = 5381
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = (((hash << 5) + hash) + CByte(AscW(str(CInt(i)))) And UInteger.MaxValue)
        Next

        Return hash
    End Function
    Public Shared Function ELFHash(str As String) As UInteger
        Dim hash As UInteger = 0
        Dim x As UInteger = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = (hash << 4) + CByte(AscW(str(CInt(i))))
            x = hash And &HF0000000UI

            If x <> 0 Then
                hash = hash Xor (x >> 24)
            End If
            hash = hash And Not x
        Next

        Return hash
    End Function
    Public Shared Function FNVHash(str As String) As UInteger
        Const fnv_prime As UInteger = &H811C9DC5UI
        Dim hash As ULong = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = (hash * fnv_prime) And UInteger.MaxValue
            hash = hash Xor CByte(AscW(str(CInt(i))))
        Next

        Return hash
    End Function

    Public Shared Function JSHash(str As String) As UInteger
        Dim hash As ULong = 1315423911
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = ((hash Xor ((hash << 5) + CByte(AscW(str(CInt(i)))) + (hash >> 2))) And UInteger.MaxValue)
        Next

        Return hash
    End Function
    Public Shared Function PJWHash(str As String) As UInteger
        Const BitsInUnsignedInt As UInteger = CUInt(4 * 8)
        Const ThreeQuarters As UInteger = CUInt((BitsInUnsignedInt * 3) / 4)
        Const OneEighth As UInteger = CUInt(BitsInUnsignedInt \ 8)
        Const HighBits As UInteger = CUInt(&HFFFFFFFFUI) << CInt(BitsInUnsignedInt - OneEighth)
        Dim hash As UInteger = 0
        Dim test As UInteger = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = (hash << CInt(OneEighth)) + CByte(AscW(str(CInt(i))))
            test = hash And HighBits

            If test <> 0 Then
                hash = ((hash Xor (test >> CInt(ThreeQuarters))) And (Not HighBits))
            End If
        Next

        Return hash
    End Function

    Public Shared Function RSHash(str As String) As UInteger
        Dim b As UInteger = 378551
        Dim a As ULong = 63689
        Dim hash As ULong = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = (hash * a + CByte(AscW(str(CInt(i))))) And UInteger.MaxValue
            a = (a * b) And UInteger.MaxValue
        Next

        Return hash
    End Function
    Public Shared Function SDBMHash(str As String) As UInteger
        Dim hash As ULong = 0
        Dim i As UInteger = 0

        For i = 0 To str.Length - 1
            hash = ((CByte(AscW(str(CInt(i)))) + (hash << 6) + (hash << 16) - hash) And UInteger.MaxValue)
        Next

        Return hash
    End Function










#End Region
#Region "NEW CIPHERS"
#Region "Playfair Cipher"
    Private Shared Function [Mod](a As Integer, b As Integer) As Integer
        Return (a Mod b + b) Mod b
    End Function

    Private Shared Function FindAllOccurrences(str As String, value As Char) As List(Of Integer)
        Dim indexes As New List(Of Integer)()

        Dim index As Integer = 0
        While index <> -1
            index = str.IndexOf(value, index)
            If index <> -1 Then
                indexes.Add(index)
                index += 1
            End If
        End While

        Return indexes
    End Function

    Private Shared Function RemoveAllDuplicates(str As String, indexes As List(Of Integer)) As String
        Dim retVal As String = str

        For i As Integer = indexes.Count - 1 To 1 Step -1
            retVal = retVal.Remove(indexes(i), 1)
        Next

        Return retVal
    End Function

    Private Shared Function GenerateKeySquare(key As String) As Char(,)
        Dim keySquare As Char(,) = New Char(4, 4) {}
        Dim defaultKeySquare As String = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        Dim tempKey As String = If(String.IsNullOrEmpty(key), "CIPHER", key.ToUpper())

        tempKey = tempKey.Replace("J", "")
        tempKey += defaultKeySquare

        For i As Integer = 0 To 24
            Dim indexes As List(Of Integer) = FindAllOccurrences(tempKey, defaultKeySquare(i))
            tempKey = RemoveAllDuplicates(tempKey, indexes)
        Next

        tempKey = tempKey.Substring(0, 25)

        For i As Integer = 0 To 24
            keySquare((i \ 5), (i Mod 5)) = tempKey(i)
        Next

        Return keySquare
    End Function

    Private Shared Sub GetPosition(ByRef keySquare As Char(,), ch As Char, ByRef row As Integer, ByRef col As Integer)
        If ch = "J"c Then
            GetPosition(keySquare, "I"c, row, col)
        End If

        For i As Integer = 0 To 4
            For j As Integer = 0 To 4
                If keySquare(i, j) = ch Then
                    row = i
                    col = j
                End If
            Next
        Next
    End Sub

    Private Shared Function SameRow(ByRef keySquare As Char(,), row As Integer, col1 As Integer, col2 As Integer, encipher As Integer) As Char()
        Return New Char() {keySquare(row, [Mod]((col1 + encipher), 5)), keySquare(row, [Mod]((col2 + encipher), 5))}
    End Function

    Private Shared Function SameColumn(ByRef keySquare As Char(,), col As Integer, row1 As Integer, row2 As Integer, encipher As Integer) As Char()
        Return New Char() {keySquare([Mod]((row1 + encipher), 5), col), keySquare([Mod]((row2 + encipher), 5), col)}
    End Function

    Private Shared Function SameRowColumn(ByRef keySquare As Char(,), row As Integer, col As Integer, encipher As Integer) As Char()
        Return New Char() {keySquare([Mod]((row + encipher), 5), [Mod]((col + encipher), 5)), keySquare([Mod]((row + encipher), 5), [Mod]((col + encipher), 5))}
    End Function

    Private Shared Function DifferentRowColumn(ByRef keySquare As Char(,), row1 As Integer, col1 As Integer, row2 As Integer, col2 As Integer) As Char()
        Return New Char() {keySquare(row1, col2), keySquare(row2, col1)}
    End Function

    Private Shared Function RemoveOtherChars(input As String) As String
        Dim output As String = input

        Dim i As Integer = 0
        While i < output.Length
            If Not Char.IsLetter(output(i)) Then
                output = output.Remove(i, 1)
            End If
            i += 1
        End While

        Return output
    End Function

    Private Shared Function AdjustOutput(input As String, output As String) As String
        Dim retVal As New StringBuilder(output)

        For i As Integer = 0 To input.Length - 1
            If Not Char.IsLetter(input(i)) Then
                retVal = retVal.Insert(i, input(i).ToString())
            End If

            If Char.IsLower(input(i)) Then
                retVal(i) = Char.ToLower(retVal(i))
            End If
        Next

        Return retVal.ToString()
    End Function

    Private Shared Function Cipher(input As String, key As String, encipher As Boolean) As String
        Dim retVal As String = String.Empty
        Dim keySquare As Char(,) = GenerateKeySquare(key)
        Dim tempInput As String = RemoveOtherChars(input)
        Dim e As Integer = If(encipher, 1, -1)

        If (tempInput.Length Mod 2) <> 0 Then
            tempInput += "X"
        End If

        For i As Integer = 0 To tempInput.Length - 1 Step 2
            Dim row1 As Integer = 0
            Dim col1 As Integer = 0
            Dim row2 As Integer = 0
            Dim col2 As Integer = 0

            GetPosition(keySquare, Char.ToUpper(tempInput(i)), row1, col1)
            GetPosition(keySquare, Char.ToUpper(tempInput(i + 1)), row2, col2)

            If row1 = row2 AndAlso col1 = col2 Then
                retVal += New String(SameRowColumn(keySquare, row1, col1, e))
            ElseIf row1 = row2 Then
                retVal += New String(SameRow(keySquare, row1, col1, col2, e))
            ElseIf col1 = col2 Then
                retVal += New String(SameColumn(keySquare, col1, row1, row2, e))
            Else
                retVal += New String(DifferentRowColumn(keySquare, row1, col1, row2, col2))
            End If
        Next

        retVal = AdjustOutput(input, retVal)

        Return retVal
    End Function

    Public Shared Function Encipher(input As String, key As String) As String
        Return Cipher(input, key, True)
    End Function
    Public Shared Function Decipher1(input As String, key As String) As String
        Return Cipher(input, key, False)
    End Function

    ''Dim text As String = "Hello World"
    ''Dim cipherText As String = Encipher(text, "cipher")
    ''Dim plainText As String = Decipher1(cipherText, "cipher")

#End Region
#Region "Simple Substitution Cipher"
    Private Shared Function Cipher(input As String, oldAlphabet As String, newAlphabet As String, ByRef output As String) As Boolean
        output = String.Empty

        If oldAlphabet.Length <> newAlphabet.Length Then
            Return False
        End If

        For i As Integer = 0 To input.Length - 1
            Dim oldCharIndex As Integer = oldAlphabet.IndexOf(Char.ToLower(input(i)))

            If oldCharIndex >= 0 Then
                output += If(Char.IsUpper(input(i)), Char.ToUpper(newAlphabet(oldCharIndex)), newAlphabet(oldCharIndex))
            Else
                output += input(i)
            End If
        Next

        Return True
    End Function

    Public Shared Function Encipher(input As String, cipherAlphabet As String, ByRef output As String) As Boolean
        Dim plainAlphabet As String = "abcdefghijklmnopqrstuvwxyz"
        Return Cipher(input, plainAlphabet, cipherAlphabet, output)
    End Function

    Public Shared Function Decipher(input As String, cipherAlphabet As String, ByRef output As String) As Boolean
        Dim plainAlphabet As String = "abcdefghijklmnopqrstuvwxyz"
        Return Cipher(input, cipherAlphabet, plainAlphabet, output)
    End Function

    ''Dim text As String = "The quick brown fox jumps over the lazy dog"
    ''Dim cipherAlphabet As String = "yhkqgvxfoluapwmtzecjdbsnri"
    ''Dim cipherText As String
    ''Dim plainText As String
    ''Dim encipherResult As Boolean = Encipher(text, cipherAlphabet, cipherText)
    ''Dim decipherResult As Boolean = Decipher(cipherText, cipherAlphabet, plainText)
#End Region
#Region "Transposition Cipher"
    Private Shared Function GetShiftIndexes(key As String) As Integer()
        Dim keyLength As Integer = key.Length
        Dim indexes As Integer() = New Integer(keyLength - 1) {}
        Dim sortedKey As New List(Of KeyValuePair(Of Integer, Char))()
        Dim i As Integer

        For i = 0 To keyLength - 1
            sortedKey.Add(New KeyValuePair(Of Integer, Char)(i, key(i)))
        Next

        sortedKey.Sort(Function(pair1 As KeyValuePair(Of Integer, Char), pair2 As KeyValuePair(Of Integer, Char)) pair1.Value.CompareTo(pair2.Value))

        For i = 0 To keyLength - 1
            indexes(sortedKey(i).Key) = i
        Next

        Return indexes
    End Function

    Public Shared Function Encipher(input As String, key As String, padChar As Char) As String
        input = If((input.Length Mod key.Length = 0), input, input.PadRight(input.Length - (input.Length Mod key.Length) + key.Length, padChar))
        Dim output As New StringBuilder()
        Dim totalChars As Integer = input.Length
        Dim totalColumns As Integer = key.Length
        Dim totalRows As Integer = CInt(Math.Truncate(Math.Ceiling(CDbl(totalChars) / totalColumns)))
        Dim rowChars As Char(,) = New Char(totalRows - 1, totalColumns - 1) {}
        Dim colChars As Char(,) = New Char(totalColumns - 1, totalRows - 1) {}
        Dim sortedColChars As Char(,) = New Char(totalColumns - 1, totalRows - 1) {}
        Dim currentRow As Integer, currentColumn As Integer, i As Integer, j As Integer
        Dim shiftIndexes As Integer() = GetShiftIndexes(key)

        For i = 0 To totalChars - 1
            currentRow = i \ totalColumns
            currentColumn = i Mod totalColumns
            rowChars(currentRow, currentColumn) = input(i)
        Next

        For i = 0 To totalRows - 1
            For j = 0 To totalColumns - 1
                colChars(j, i) = rowChars(i, j)
            Next
        Next

        For i = 0 To totalColumns - 1
            For j = 0 To totalRows - 1
                sortedColChars(shiftIndexes(i), j) = colChars(i, j)
            Next
        Next

        For i = 0 To totalChars - 1
            currentRow = i \ totalRows
            currentColumn = i Mod totalRows
            output.Append(sortedColChars(currentRow, currentColumn))
        Next

        Return output.ToString()
    End Function

    Public Shared Function Decipher(input As String, key As String) As String
        Dim output As New StringBuilder()
        Dim totalChars As Integer = input.Length
        Dim totalColumns As Integer = CInt(Math.Truncate(Math.Ceiling(CDbl(totalChars) / key.Length)))
        Dim totalRows As Integer = key.Length
        Dim rowChars As Char(,) = New Char(totalRows - 1, totalColumns - 1) {}
        Dim colChars As Char(,) = New Char(totalColumns - 1, totalRows - 1) {}
        Dim unsortedColChars As Char(,) = New Char(totalColumns - 1, totalRows - 1) {}
        Dim currentRow As Integer, currentColumn As Integer, i As Integer, j As Integer
        Dim shiftIndexes As Integer() = GetShiftIndexes(key)

        For i = 0 To totalChars - 1
            currentRow = i \ totalColumns
            currentColumn = i Mod totalColumns
            rowChars(currentRow, currentColumn) = input(i)
        Next

        For i = 0 To totalRows - 1
            For j = 0 To totalColumns - 1
                colChars(j, i) = rowChars(i, j)
            Next
        Next

        For i = 0 To totalColumns - 1
            For j = 0 To totalRows - 1
                unsortedColChars(i, j) = colChars(i, shiftIndexes(j))
            Next
        Next

        For i = 0 To totalChars - 1
            currentRow = i \ totalRows
            currentColumn = i Mod totalRows
            output.Append(unsortedColChars(currentRow, currentColumn))
        Next

        Return output.ToString()
    End Function
    ''Dim text As String = "The quick brown fox jumps over the lazy dog"
    ''Dim key As String = "pangram"
    ''Dim cipherText As String = Encipher(text, Key, "-"c)
    ''Dim plainText As String = Decipher(cipherText, Key)
#End Region
#End Region
#Region "URL Encoding"
    Public Shared Function EncodeURL(data As String) As String
        Dim result As New StringBuilder(data.Length)

        For Each c As Char In data
            If ("a"c <= c AndAlso c <= "z"c) OrElse ("A"c <= c AndAlso c <= "Z"c) OrElse ("0"c <= c AndAlso c <= "9"c) Then
                result.Append(c)
            Else
                result.Append("%"c)
                result.Append(DecimalToHexadecimal(AscW(c)).PadLeft(2, "0"c))
            End If
        Next

        Return result.ToString()
    End Function

    Private Shared Function DecimalToHexadecimal(dec As Integer) As String
        If dec < 1 Then Return "0"

        Dim hex As Integer = dec
        Dim hexStr As String = String.Empty

        While dec > 0
            hex = dec Mod 16

            If hex < 10 Then
                hexStr = hexStr.Insert(0, Convert.ToChar(hex + 48).ToString())
            Else
                hexStr = hexStr.Insert(0, Convert.ToChar(hex + 55).ToString())
            End If

            dec \= 16
        End While

        Return hexStr
    End Function
#End Region
#Region "URL Decoding"
    Public Shared Function DecodeURL(data As String) As String
        Dim result As New StringBuilder(data.Length)

        For i As Integer = 0 To data.Length - 1
            If data(i) = "%"c Then
                result.Append(ChrW(HexadecimalToDecimal(data.Substring(i + 1, 2))))
                i += 2
            Else
                result.Append(data(i))
            End If
        Next

        Return result.ToString()
    End Function

    Private Shared Function HexadecimalToDecimal(hex As String) As Integer
        hex = hex.ToUpper()

        Dim hexLength As Integer = hex.Length
        Dim dec As Double = 0

        For i As Integer = 0 To hexLength - 1
            Dim b As Byte = CByte(AscW(hex(i)))

            If b >= 48 AndAlso b <= 57 Then
                b -= 48
            ElseIf b >= 65 AndAlso b <= 70 Then
                b -= 55
            End If

            dec += b * Math.Pow(16, ((hexLength - i) - 1))
        Next

        Return CInt(Math.Truncate(dec))
    End Function
#End Region
#End Region



#End Region
#Region "Functions"
    Dim translation As New Dictionary(Of String, String)
    Public Function GenerateRandomString(ByRef lenStr As Integer, Optional ByVal upper As Boolean = False) As String
        Dim rand As New Random()
        Dim allowableChars() As Char =
            TextBoxX13.Text.ToCharArray()
        Dim final As New System.Text.StringBuilder
        Do
            final.Append(allowableChars(rand.Next(0, allowableChars.Length)))
        Loop Until final.Length = lenStr
        Debug.WriteLine(final.Length)
        Return If(upper, final.ToString.ToUpper(), final.ToString)
    End Function
    Private Function GetBytesToHexadeciString(ByVal bytes As Byte()) As String
        Dim output As String = String.Empty
        Dim i As Integer = 0
        Do While i < bytes.Length
            output += bytes(i).ToString("X2")
            i += 1
        Loop
        Return output
    End Function
    Public Function RandomVariable(ByVal minamount As Integer, ByVal maxamount As Integer) As String
        Dim Rand As New Random
        Dim TheVariable As String = Nothing
        Dim CharactersToUse As String = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPLKHJJGFDSAZXCVBNM1234567890"
        For x As Integer = 1 To Rand.Next(minamount + 1, maxamount)
            Dim PickAChar As Integer = Int((CharactersToUse.Length - 2) * Rnd()) + 1
            TheVariable += (CharactersToUse(PickAChar))
        Next
        Dim letters As String = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPLKHJJGFDSAZXCVBNM"
        Return letters(Rand.Next(0, letters.Length - 1)) + TheVariable
    End Function
    Function Generate() As String
        Dim pool() As String = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
                                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
                                "r", "s", "t", "u", "v", "w", "x", "y", "z"}
        Dim chars As String = Nothing
        For i = 0 To 8
            chars += pool(Rnd() * 61)
        Next
        Return chars
    End Function
    Public Function random_key(ByVal lenght As Integer) As String
        Randomize()
        Dim s As New System.Text.StringBuilder("")
        Dim b() As Char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray()
        For i As Integer = 1 To lenght
            Randomize()
            Dim z As Integer = Int(((b.Length - 2) - 0 + 1) * Rnd()) + 1
            s.Append(b(z))
        Next
        Return s.ToString
    End Function
#End Region
#Region "COMBOBOXES VISIBLES"
    Private Sub ComboBox1_SelectedIndexChanged(sender As Object, e As EventArgs) Handles ComboBox1.SelectedIndexChanged
        Try
            If ComboBox1.SelectedItem = "ATOM-128" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "HAZZ-15" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "RIPEMD160Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "SHA1Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "SHA256Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "SHA348Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "SHA512Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "MD5Hash" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Polymorphic Stairs" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "MD5" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Stairs" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Polymorphic RC4" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "3DES" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "AES" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "RC2" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "CustomXOR" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "DES" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "GILA7" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "ESAB-46" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "MEGAN-35" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "ZONG-22" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "TRIPO-5" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "TIGO-3FX" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "FERON-74" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Base64" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "ROT-13" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "RSA" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Reverse" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "HEX" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Binary" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Custom_Line" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "~Draven's Algorithm" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "UpperCase" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "LowerCase" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Compression(GZip)" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Compression(Deflate)" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "ZARA128" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "EnvY'S Encryption" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Caesar Cipher" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = True
                Label29.Visible = True
            ElseIf ComboBox1.SelectedItem = "Rijindael" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "XOR" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "RC4" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "RSM" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Pr0t3" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Line" Then
                PWD.Enabled = False
                PWD.Visible = False
                Label21.Visible = False
                Label22.Visible = False
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Vernam" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Encryptvg" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "Encrypt" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            ElseIf ComboBox1.SelectedItem = "TripleDES" Then
                PWD.Enabled = True
                PWD.Visible = True
                Label21.Visible = True
                Label22.Visible = True
                TextBoxX10.Visible = False
                Label29.Visible = False
            End If
        Catch ex As Exception
        End Try
    End Sub
    Private Sub ReactorComboBox1_SelectedIndexChanged(sender As Object, e As EventArgs) Handles ReactorComboBox1.SelectedIndexChanged
        Try
            If ReactorComboBox1.SelectedItem = "ATOM-128" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Atbash Cipher" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Reverse" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Caesar Cipher" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = True
                Label31.Visible = True

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "HAZZ-15" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Morse Code" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "HEX" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "3DES" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "AES" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "TripleDES" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "RC2" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "RC4" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic Stairs" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Stairs" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "CustomXOR" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "DES" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "GILA7" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Pr0t3" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "ESAB-46" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "MEGAN-35" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "ZONG-22" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "TRIPO-5" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "TIGO-3FX" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "FERON-74" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Base64" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "ROT-13" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "RSA" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Binary" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Custom_Line" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "~Draven's Algorithm" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "UpperCase ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "LowerCase ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = False

            ElseIf ReactorComboBox1.SelectedItem = "Compression(GZip)" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Compression(Deflate)" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "ZARA128" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic RC4" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Vigenere" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "RIPEMD160Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "SHA1Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                Me.Logintextbox1.AutoSize = False
                Me.Logintextbox1.Width = 628
                Me.Logintextbox1.Height = 279
                Logintextbox1.Location = New Point(11, 44)
                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "SHA256Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "SHA348Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "SHA512Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False


                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "MD5Hash ( Can't Decrypt )" Then
                ReactorTextBox1.Enabled = False
                ReactorTextBox1.Visible = False
                Label1.Visible = False
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = False
                ReactorButton2.Enabled = False
            ElseIf ReactorComboBox1.SelectedItem = "Vernam" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "EnvY'S Encryption" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "Rinjandel" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False

                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            ElseIf ReactorComboBox1.SelectedItem = "XOR" Then
                ReactorTextBox1.Enabled = True
                ReactorTextBox1.Visible = True
                Label1.Visible = True
                TextBoxX11.Visible = False
                Label31.Visible = False
                PictureBox6.Visible = True
                ReactorButton2.Enabled = True
            End If
        Catch ex As Exception
        End Try
    End Sub
#End Region
#Region "TIMERS"
    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        If CheckBox4.Checked = True Then
            TabItem5.Visible = False
        Else
            TabItem5.Visible = True
        End If
        If CheckBox5.Checked = True Then
            TabItem11.Visible = False
        Else
            TabItem11.Visible = True
        End If
        RandomPool2.ForeColor = ColorPickerButton2.SelectedColor
        RandomPool2.BackColor = ColorPickerButton1.SelectedColor
        TextBox39.Text = Logintextbox1.Text.GetHashCode
        Label352.Text = "Methods [ " + ListView1.Items.Count.ToString + " ]"
        Label350.Text = "Methods [ " + ListView2.Items.Count.ToString + " ]"
        If TabControl1.SelectedTab.Text = "Text Cryption" Then
            TitleText = "Text Cryption ( Made by James reborn )"
        End If
        If TabControl1.SelectedTab.Text = "Advanced Text Cryption" Then
            TitleText = "Advanced Text Cryption ( Made by James reborn )"
        End If
        If TabControl1.SelectedTab.Text = "File Cryption" Then
            TitleText = "File Cryption ( Made by James reborn )"
        End If
        If TabControl1.SelectedTab.Text = "Misc" Then
            TitleText = "Miscellaneous ( Made by James reborn )"
        End If
        If TabControl1.SelectedTab.Text = "Methods / Gen Settings" Then
            TitleText = "Methods / Gen Settings ( Made by James reborn )"
        End If
        If ListBox1.SelectedItem = Nothing Then
            ContextMenuStrip1.Enabled = False
        Else
            ContextMenuStrip1.Enabled = True
        End If
        If My.Computer.Keyboard.CapsLock = True Then
            Label34.Text = "YES"
            Label35.Text = "YES"
            Label37.Text = "YES"
            Label39.Text = "YES"
        Else
            Label34.Text = "NO"
            Label35.Text = "NO"
            Label37.Text = "NO"
            Label39.Text = "NO"
        End If
        TextBox6.Text = Clipboard.GetText
        Try
            If Clipboard.ContainsImage Then
                PictureBox1.Image = CType(Clipboard.GetData(System.Windows.Forms.DataFormats.Bitmap), Bitmap)
            ElseIf Clipboard.ContainsFileDropList = True Then
                PictureBox1.Load(Clipboard.GetFileDropList(0))
            ElseIf Clipboard.ContainsImage = False Then
                PictureBox1.Image = Nothing
            End If
        Catch ex As Exception
        End Try
        Label4.Text = "Selected Characters [ 0 ]".Replace("0", Logintextbox1.SelectedText.Length)
        Dim xtt$ = Logintextbox1.Text
        Label5.Text = "Number of Characters [ 0 ]".Replace("0", xtt.Length)
        Me.Label6.Text = "[ " + Conversions.ToString(Me.NumericUpDown2.Value) + " Length ] + 1"
        Label9.Text = "Methods [ " + ReactorComboBox1.Items.Count.ToString + " ]"
        Label16.Text = "Amount of Characters [ " + NumericUpDown3.Value.ToString + " ] + 1"
        Label17.Text = "Methods [ " + ComboBox1.Items.Count.ToString + " ]"
        Label18.Text = "Methods [ " + ComboBox2.Items.Count.ToString + " ]"
        Label258.Text = "Methods [ " + ComboBox3.Items.Count.ToString + " ]"
        Label19.Text = "Selected Characters [ 0 ]".Replace("0", RichTextBox1.SelectedText.Length)
        Dim xt = RichTextBox1.Text
        Label20.Text = "Number of Characters [ 0 ]".Replace("0", xt.Length)
        Dim xt1 = PWD.Text
        Label23.Text = "Selected Characters [ 0 ]".Replace("0", TextBox4.SelectedText.Length)
        Dim gay = TextBox4.Text
        Label24.Text = "Number of Characters [ 0 ]".Replace("0", gay.Length)
        Dim xt90 = TextBox8.Text
        Label26.Text = "Number of Characters [ 0 ]".Replace("0", xt90.Length)
        Label25.Text = "Selected Characters [ 0 ]".Replace("0", TextBox8.SelectedText.Length)
        Dim lineCount As Integer = Logintextbox1.Lines.Count + 1
        Label351.Text = "Number of Lines in Textbox [ 0 ]".Replace("0", Logintextbox1.Lines.Length)
    End Sub
    Private Sub Timer3_Tick(sender As Object, e As EventArgs) Handles Timer3.Tick
        Dim random As New Random
        If RadioButton87.Checked = True Then
            RandomPool2.Range = CryptString_1(random.Next)
        Else
        End If
        If RadioButton86.Checked = True Then
            RandomPool2.Range = Atom128_Encode(random.Next)
        Else
        End If
        If RadioButton85.Checked = True Then
            RandomPool2.Range = BASE64_Encode(random.Next)
        Else
        End If
        If RadioButton84.Checked = True Then
            RandomPool2.Range = ConvertToBinary(random.Next)
        Else
        End If
        If RadioButton83.Checked = True Then
            RandomPool2.Range = Zip_deflate(random.Next)
        Else
        End If
        If RadioButton82.Checked = True Then
            RandomPool2.Range = Zip_G(random.Next)
        Else
        End If
        If RadioButton81.Checked = True Then
            RandomPool2.Range = Encrypt_CustomLine(random.Next)
        Else
        End If
        If RadioButton80.Checked = True Then
            RandomPool2.Range = ESAB46_Encode(random.Next)
        Else
        End If
        If RadioButton79.Checked = True Then
            RandomPool2.Range = FERON74_Encode(random.Next)
        Else
        End If
        If RadioButton78.Checked = True Then
            RandomPool2.Range = GILA7_Encode(random.Next)
        Else
        End If
        If RadioButton77.Checked = True Then
            RandomPool2.Range = HAZZ15_Encode(random.Next)
        Else
        End If
        If RadioButton76.Checked = True Then
            RandomPool2.Range = String2Hex(random.Next)
        Else
        End If
        If RadioButton75.Checked = True Then
            RandomPool2.Range = MD5Hash(random.Next)
        Else
        End If
        If RadioButton74.Checked = True Then
            RandomPool2.Range = MEGAN35_Encode(random.Next)
        Else
        End If
        If RadioButton73.Checked = True Then
            RandomPool2.Range = pr0t3_encrypt(random.Next)
        Else
        End If
        If RadioButton72.Checked = True Then
            RandomPool2.Range = StrReverse(random.Next)
        Else
        End If
        If RadioButton71.Checked = True Then
            RandomPool2.Range = RIPEMD160Hash(random.Next)
        Else
        End If
        If RadioButton70.Checked = True Then
            RandomPool2.Range = Rot13(random.Next)
        Else
        End If
        If RadioButton69.Checked = True Then
            RandomPool2.Range = RSA_Encrypt(random.Next)
        Else
        End If
        If RadioButton68.Checked = True Then
            RandomPool2.Range = SHA1Hash(random.Next)
        Else
        End If
        If RadioButton67.Checked = True Then
            RandomPool2.Range = SHA256Hash(random.Next)
        Else
        End If
        If RadioButton66.Checked = True Then
            RandomPool2.Range = SHA348Hash(random.Next)
        Else
        End If
        If RadioButton65.Checked = True Then
            RandomPool2.Range = SHA512Hash(random.Next)
        Else
        End If
        If RadioButton64.Checked = True Then
            RandomPool2.Range = TIGO3FX_Encode(random.Next)
        Else
        End If
        If RadioButton63.Checked = True Then
            RandomPool2.Range = TRIPO5_Encode(random.Next)
        Else
        End If
        If RadioButton62.Checked = True Then
            RandomPool2.Range = ZARA128_Encode(random.Next)
        Else
        End If
        If RadioButton61.Checked = True Then
            RandomPool2.Range = ZONG22_Encode(random.Next)
        Else
        End If
        If RadioButton60.Checked = True Then
            RandomPool2.Range = HMACMD5(random.Next)
        Else
        End If
        If RadioButton59.Checked = True Then
            RandomPool2.Range = HMACRIPEMD160(random.Next)
        Else
        End If
        If RadioButton58.Checked = True Then
            RandomPool2.Range = HMACSHA1(random.Next)
        Else
        End If
        If RadioButton57.Checked = True Then
            RandomPool2.Range = HMACSHA256(random.Next)
        Else
        End If
        If RadioButton56.Checked = True Then
            RandomPool2.Range = HMACSHA384(random.Next)
        Else
        End If
        If RadioButton55.Checked = True Then
            RandomPool2.Range = HMACSHA512(random.Next)
        Else
        End If
        If RadioButton54.Checked = True Then
            RandomPool2.Range = MACTripleDES(random.Next)
        Else
        End If
        If RadioButton53.Checked = True Then
            RandomPool2.Range = EncryptSHA512Managed(random.Next)
        Else
        End If
    End Sub
#End Region
#Region "POPULATES"
    Private Sub POPULATE()
        With ListView1
            .Clear()
            ListView1.View = View.Details
            ListView1.Columns.Add("Text", 150)
            ListView1.Columns.Add("Method", 150)
            Dim row As String() = New String(3) {}
            Dim item As ListViewItem
            row(0) = BASE64_Encode(Me.TextBox4.Text)
            row(1) = "Base64"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = Atom128_Encode(Me.TextBox4.Text)
            row(1) = "ATOM-128"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = ConvertToBinary(Me.TextBox4.Text)
            row(1) = "Binary"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = Zip_deflate(Me.TextBox4.Text)
            row(1) = "Compression(Deflate)"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = Zip_G(Me.TextBox4.Text)
            row(1) = "Compression(GZip)"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = Encrypt_CustomLine(Me.TextBox4.Text)
            row(1) = "Custom_Line"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = ESAB46_Encode(Me.TextBox4.Text)
            row(1) = "ESAB-46"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = FERON74_Encode(Me.TextBox4.Text)
            row(1) = "FERON-74"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = GILA7_Encode(Me.TextBox4.Text)
            row(1) = "GILA7"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HAZZ15_Encode(Me.TextBox4.Text)
            row(1) = "HAZZ-15"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = String2Hex(Me.TextBox4.Text)
            row(1) = "HEX"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = (Me.TextBox4.Text.ToLower)
            row(1) = "LowerCase"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = MEGAN35_Encode(Me.TextBox4.Text)
            row(1) = "MEGAN-35"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = StrReverse(Me.TextBox4.Text)
            row(1) = "Reverse"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = Rot13(Me.TextBox4.Text)
            row(1) = "ROT-13"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = RSA_Encrypt(Me.TextBox4.Text)
            row(1) = "RSA"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = TIGO3FX_Encode(Me.TextBox4.Text)
            row(1) = "TIGO-3FX"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = TRIPO5_Encode(Me.TextBox4.Text)
            row(1) = "TRIPO-5"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = (Me.TextBox4.Text.ToUpper)
            row(1) = "UpperCase"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = ZARA128_Encode(Me.TextBox4.Text)
            row(1) = "ZARA128"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = ZONG22_Encode(Me.TextBox4.Text)
            row(1) = "ZONG-22"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = CryptString_1(TextBox4.Text)
            row(1) = "~Draven's Algorithm"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = pr0t3_encrypt(TextBox4.Text)
            row(1) = "Pr0t3"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = RIPEMD160Hash(TextBox4.Text)
            row(1) = "RIPEMD160Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = SHA1Hash(TextBox4.Text)
            row(1) = "SHA1Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = SHA256Hash(TextBox4.Text)
            row(1) = "SHA256Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = SHA348Hash(TextBox4.Text)
            row(1) = "SHA348Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = SHA512Hash(TextBox4.Text)
            row(1) = "SHA512Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = MD5Hash(TextBox4.Text)
            row(1) = "MD5Hash"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACMD5(TextBox4.Text)
            row(1) = "HMACMD5"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACRIPEMD160(TextBox4.Text)
            row(1) = "HMACRIPEMD160"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACSHA1(TextBox4.Text)
            row(1) = "HMACSHA1"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACSHA256(TextBox4.Text)
            row(1) = "HMACSHA256"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACSHA384(TextBox4.Text)
            row(1) = "HMACSHA384"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = HMACSHA512(TextBox4.Text)
            row(1) = "HMACSHA512"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = EncryptSHA512Managed(TextBox4.Text)
            row(1) = "EncryptSHA512Managed"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            row(0) = String.Join("/", Array.ConvertAll(TextBox4.Text.ToArray, Function(c) If(translation.Keys.Contains(c.ToString.ToUpper), translation(c.ToString.ToUpper), c.ToString)))
            row(1) = "Morse Code"
            item = New ListViewItem(row)
            ListView1.Items.Add(item)
            ListView1.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent)
        End With
    End Sub
    Private Sub POPULATE2()
        With ListView2
            .Clear()
            ListView2.View = View.Details
            ListView2.Columns.Add("Text", 150)
            ListView2.Columns.Add("Method", 150)
            Dim row As String() = New String(3) {}
            Dim item As ListViewItem
            row(0) = EnvY_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "EnvY'S Encryption"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = AES_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "AES"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = DES_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "DES"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = CustomXOR_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "CustomXOR"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = XOR_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "XOR"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = c_Encrypt(TextBox8.Text, TextBoxX9.Text)
            row(1) = "Caesar Cipher"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = RC2Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "RC2"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = rc4(TextBox8.Text, TextBoxX8.Text)
            row(1) = "RC4"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = EncryptString(TextBox8.Text, TextBoxX8.Text)
            row(1) = "3DES"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = Crypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "Stairs"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = PolyCrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "Polymorphic Stairs"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = Rijndaelcrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "Rinjandel"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = TripleDES_Encrypt(TextBox8.Text, TextBoxX8.Text)
            row(1) = "TripleDES"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = Vigenere_Cipher(TextBox8.Text, TextBoxX8.Text, True)
            row(1) = "Vigenere"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            row(0) = vernam1.x(TextBox8.Text, TextBoxX8.Text)
            row(1) = "Vernam"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            Dim POLLY As New PolyRC4(TextBoxX8.Text)
            row(0) = POLLY.Encrypt(TextBox8.Text)
            row(1) = "Polymorphic RC4"
            item = New ListViewItem(row)
            ListView2.Items.Add(item)
            ListView2.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent)
        End With
    End Sub
#End Region
    Private Shared Sub __ENCAddToList(value As Object)
        Dim _ENCList As List(Of WeakReference) = __ENCList
        Dim flag As Boolean = False
        Try
            Monitor.Enter(_ENCList, flag)
            Dim flag2 As Boolean = __ENCList.Count = __ENCList.Capacity
            If flag2 Then
                Dim num As Integer = 0
                Dim arg_44_0 As Integer = 0
                Dim num2 As Integer = __ENCList.Count - 1
                Dim num3 As Integer = arg_44_0
                While True
                    Dim arg_95_0 As Integer = num3
                    Dim num4 As Integer = num2
                    If arg_95_0 > num4 Then
                        Exit While
                    End If
                    Dim weakReference As WeakReference = __ENCList(num3)
                    flag2 = weakReference.IsAlive
                    If flag2 Then
                        Dim flag3 As Boolean = num3 <> num
                        If flag3 Then
                            __ENCList(num) = __ENCList(num3)
                        End If
                        num += 1
                    End If
                    num3 += 1
                End While
                __ENCList.RemoveRange(num, __ENCList.Count - num)
                __ENCList.Capacity = __ENCList.Count
            End If
            __ENCList.Add(New WeakReference(RuntimeHelpers.GetObjectValue(value)))
        Finally
            Dim flag3 As Boolean = flag
            If flag3 Then
                Monitor.[Exit](_ENCList)
            End If
        End Try
    End Sub
#Region "ENCRYPT/DECRYPT BUTTON"
    Private Function UnicodeStringToBytes(
    ByVal str As String) As Byte()

        Return System.Text.Encoding.Unicode.GetBytes(str)
    End Function


    Public Shared Function Byte2Char(ByVal b As Byte) As Char
        Return ChrW(b)
    End Function

    Public Shared Function Char2Byte(ByVal c As Char) As Byte
        Return AscW(c)
    End Function
    Private Sub ReactorButton1_Click(sender As Object, e As EventArgs) Handles ReactorButton1.Click
        If CheckBox1.Checked = True Then
            Try
                If ReactorComboBox1.SelectedItem = "~Draven's Algorithm" Then
                    Logintextbox1.Text = CryptString_1(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "3DES" Then
                    Logintextbox1.Text = EncryptString(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "AES" Then
                    Logintextbox1.Text = AES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Atbash Cipher" Then
                    Logintextbox1.Text = Atbash_Cipher(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ATOM-128" Then
                    Logintextbox1.Text = Atom128_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Base64" Then
                    Logintextbox1.Text = BASE64_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Binary" Then
                    Logintextbox1.Text = ConvertToBinary(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Caesar Cipher" Then
                    Logintextbox1.Text = c_Encrypt(Logintextbox1.Text, TextBoxX11.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Compression(Deflate)" Then
                    Logintextbox1.Text = Zip_deflate(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Compression(GZip)" Then
                    Logintextbox1.Text = Zip_G(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Custom_Line" Then
                    Logintextbox1.Text = Encrypt_CustomLine(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "CustomXOR" Then
                    Logintextbox1.Text = CustomXOR_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "DES" Then
                    Logintextbox1.Text = DES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "EnvY'S Encryption" Then
                    Logintextbox1.Text = EnvY_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ESAB-46" Then
                    Logintextbox1.Text = ESAB46_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "FERON-74" Then
                    Logintextbox1.Text = FERON74_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "GILA7" Then
                    Logintextbox1.Text = GILA7_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "HAZZ-15" Then
                    Logintextbox1.Text = HAZZ15_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "HEX" Then
                    Logintextbox1.Text = String2Hex(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "LowerCase ( Can't Decrypt )" Then
                    Logintextbox1.Text = Logintextbox1.Text.ToLower
                ElseIf ReactorComboBox1.SelectedItem = "MD5Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = MD5Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "MEGAN-35" Then
                    Logintextbox1.Text = MEGAN35_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Morse Code" Then
                    Logintextbox1.Text = String.Join("/", Array.ConvertAll(Logintextbox1.Text.ToArray, Function(c) If(translation.Keys.Contains(c.ToString.ToUpper), translation(c.ToString.ToUpper), c.ToString)))
                    Logintextbox1.Refresh()
                ElseIf ReactorComboBox1.SelectedItem = "Polymorphic RC4" Then
                    Dim x As New PolyRC4(ReactorTextBox1.Text)
                    Logintextbox1.Text = x.Encrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Polymorphic Stairs" Then
                    Logintextbox1.Text = PolyCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Pr0t3" Then
                    Logintextbox1.Text = pr0t3_encrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RC2" Then
                    Logintextbox1.Text = RC2Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RC4" Then
                    Logintextbox1.Text = rc4(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Reverse" Then
                    Logintextbox1.Text = ReverseString(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Rinjandel" Then
                    Logintextbox1.Text = Rijndaelcrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RIPEMD160Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = RIPEMD160Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ROT-13" Then
                    Logintextbox1.Text = Rot13(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RSA" Then
                    Logintextbox1.Text = RSA_Encrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "SHA1Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = SHA1Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "SHA256Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = SHA256Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "SHA348Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = SHA348Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "SHA512Hash ( Can't Decrypt )" Then
                    Logintextbox1.Text = SHA512Hash(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Stairs" Then
                    Logintextbox1.Text = Crypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "TIGO-3FX" Then
                    Logintextbox1.Text = TIGO3FX_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "TripleDES" Then
                    Logintextbox1.Text = TripleDES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "TRIPO-5" Then
                    Logintextbox1.Text = TRIPO5_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "UpperCase ( Can't Decrypt )" Then
                    Logintextbox1.Text = Logintextbox1.Text.ToUpper
                ElseIf ReactorComboBox1.SelectedItem = "Vernam" Then
                    Logintextbox1.Text = Convert.ToString(vernam1.x(Logintextbox1.Text, ReactorTextBox1.Text))
                ElseIf ReactorComboBox1.SelectedItem = "Vigenere" Then
                    Logintextbox1.Text = Convert.ToString(Vigenere_Cipher(Logintextbox1.Text, ReactorTextBox1.Text, True))
                ElseIf ReactorComboBox1.SelectedItem = "XOR" Then
                    Logintextbox1.Text = XOR_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ZARA128" Then
                    Logintextbox1.Text = ZARA128_Encode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ZONG-22" Then
                    Logintextbox1.Text = ZONG22_Encode(Logintextbox1.Text)
                End If
            Catch Ex As Exception
                MsgBox(Err.Description)
            End Try
        Else
            BackgroundWorker2.RunWorkerAsync()
        End If
    End Sub
    Private Sub ReactorButton2_Click(sender As Object, e As EventArgs) Handles ReactorButton2.Click
        If CheckBox2.Checked = True Then
            Try
                If ReactorComboBox1.SelectedItem = "~Draven's Algorithm" Then
                    Logintextbox1.Text = DecryptString_1(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "3DES" Then
                    Logintextbox1.Text = DecryptString(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "AES" Then
                    Logintextbox1.Text = AES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Atbash Cipher" Then
                    Logintextbox1.Text = Atbash_Cipher(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ATOM-128" Then
                    Dim cost As String
                    cost = Atom128_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "Base64" Then
                    Logintextbox1.Text = BASE64_Decode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Binary" Then
                    Logintextbox1.Text = ConvertToAscii(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Caesar Cipher" Then
                    Logintextbox1.Text = c_Decrypt(Logintextbox1.Text, TextBoxX11.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Compression(Deflate)" Then
                    Logintextbox1.Text = UnZip_deflate(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Compression(GZip)" Then
                    Logintextbox1.Text = UnZip_G(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Custom_Line" Then
                    Logintextbox1.Text = Decrypt_CustomLine(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "CustomXOR" Then
                    Logintextbox1.Text = CustomXOR_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "DES" Then
                    Logintextbox1.Text = DES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "EnvY'S Encryption" Then
                    Logintextbox1.Text = EnvY_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ESAB-46" Then
                    Dim cost As String
                    cost = ESAB46_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "FERON-74" Then
                    Dim cost As String
                    cost = FERON74_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "GILA7" Then
                    Dim cost As String
                    cost = GILA7_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "HAZZ-15" Then
                    Dim cost As String
                    cost = HAZZ15_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "HEX" Then
                    Logintextbox1.Text = Hex2String(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "MEGAN-35" Then
                    Dim cost As String
                    cost = MEGAN35_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "Morse Code" Then
                    Logintextbox1.Text = String.Concat(Array.ConvertAll(Logintextbox1.Text.Split("/"c), Function(s) If(translation.Values.Contains(s), translation.First(Function(kvp) kvp.Value = s).Key, s)))
                ElseIf ReactorComboBox1.SelectedItem = "Polymorphic RC4" Then
                    Dim Y As New PolyRC4(ReactorTextBox1.Text)
                    Logintextbox1.Text = Y.Decrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Polymorphic Stairs" Then
                    Logintextbox1.Text = PolyDeCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Pr0t3" Then
                    Logintextbox1.Text = pr0t3_decrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RC2" Then
                    Logintextbox1.Text = RC2Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RC4" Then
                    Logintextbox1.Text = rc4(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Reverse" Then
                    Logintextbox1.Text = ReverseString(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Rinjandel" Then
                    Logintextbox1.Text = RijndaelDecrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ROT-13" Then
                    Logintextbox1.Text = Rot13(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "RSA" Then
                    Logintextbox1.Text = RSA_Decrypt(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Stairs" Then
                    Logintextbox1.Text = DeCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "TIGO-3FX" Then
                    Dim cost As String
                    cost = TIGO3FX_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "TripleDES" Then
                    Logintextbox1.Text = TripleDES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "TRIPO-5" Then
                    Dim cost As String
                    cost = TRIPO5_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                ElseIf ReactorComboBox1.SelectedItem = "Vernam" Then
                    Logintextbox1.Text = Vernam(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "Vigenere" Then
                    Logintextbox1.Text = Convert.ToString(Vigenere_Cipher(Logintextbox1.Text, ReactorTextBox1.Text, False))
                ElseIf ReactorComboBox1.SelectedItem = "XOR" Then
                    Logintextbox1.Text = XOR_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ZARA128" Then
                    Logintextbox1.Text = ZARA128_Decode(Logintextbox1.Text)
                ElseIf ReactorComboBox1.SelectedItem = "ZONG-22" Then
                    Dim cost As String
                    cost = ZONG22_Decode(Logintextbox1.Text)
                    cost = Replace(cost, "%20", " ")
                    cost = Replace(cost, "%3F", "?")
                    cost = Replace(cost, "%2C", ",")
                    Logintextbox1.Text = cost
                End If
            Catch ex As Exception
                MsgBox(Err.Description)
            End Try
        Else
            BackgroundWorker3.RunWorkerAsync()
        End If
    End Sub
#End Region
    Private Sub Logintextbox1_DoubleClick(sender As Object, e As EventArgs)
        Logintextbox1.SelectAll()

    End Sub
    Private Sub ButtonX2_Click(sender As Object, e As EventArgs) Handles ButtonX2.Click
        Clipboard.SetText(String.Concat(New String() {Logintextbox1.Text}))
        MessageBox.Show("All text has been successfully copied to your clipboard.", "Complete !!!", MessageBoxButtons.OK, MessageBoxIcon.Asterisk)
    End Sub
    Private Sub ButtonX3_Click(sender As Object, e As EventArgs) Handles ButtonX3.Click
        Logintextbox1.Clear()

    End Sub
    Private Sub DisplayValue(ByVal source As TextBox)
        ' Don't recurse.
        Static ignore_events As Boolean = False
        If ignore_events Then Exit Sub
        ignore_events = True

        ' Get the value.
        Dim txt As String
        Dim value As Long
        Try
            Select Case source.Name
                Case "Logintextbox1"
                    value = Long.Parse(source.Text)
                Case "txtHexadecimal"
                    txt = UCase(Trim(source.Text))
                    If txt.StartsWith("&H") Then txt = txt.Substring(2)
                    value = Long.Parse(txt, Globalization.NumberStyles.HexNumber)
                Case "txtOctal"
                    txt = UCase(Trim(source.Text))
                    If Not txt.StartsWith("&O") Then txt = "&O" & txt
                    value = CLng(txt)

            End Select
        Catch ex As Exception

        End Try

        ' Display the value in different formats.

        If source.Name <> "txtHexadecimal" Then
            txtHexadecimal.Text = "0x" + value.ToString("X")
        End If
        If source.Name <> "txtOctal" Then
            txtOctal.Text = "&O" & Oct$(value)
        End If


        ignore_events = False
    End Sub
    Private Sub TEXTENCRYPTIONANDDECRYPTION_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        SetStyle(ControlStyles.DoubleBuffer, True)
        SetStyle(ControlStyles.AllPaintingInWmPaint, True)
        SetStyle(ControlStyles.UserPaint, True)
        SetStyle(ControlStyles.SupportsTransparentBackColor, False)
        SetStyle(ControlStyles.Opaque, False)
        SetStyle(ControlStyles.OptimizedDoubleBuffer, True)
        SetStyle(ControlStyles.ResizeRedraw, True)
        Try
            StyleManager1.ManagerStyle = settings.Theme
        Catch ex As Exception
            StyleManager1.ManagerStyle = eStyle.Metro
        End Try
        ColorPickerButton2.SelectedColor = Color.Black
        ColorPickerButton1.SelectedColor = Color.White
        If IO.File.Exists(rundum) Then
            ListBox1.Items.AddRange(IO.File.ReadAllLines(rundum))
        End If
        ReactorComboBox1.SelectedIndex = 0
        ComboBox1.SelectedIndex = 0
        ComboBox2.SelectedIndex = 0
        ComboBox3.SelectedIndex = 0
        Me.FlatTextBox1.Visible = False
        TextBox11.Visible = False
        Timer1.Start()
        BackgroundWorker5.RunWorkerAsync()
    End Sub
    Private Sub TEXTENCRYPTIONANDDECRYPTION_FormClosing(sender As Object, e As FormClosingEventArgs) Handles MyBase.FormClosing
        My.Settings.Save()
        settings.Theme = StyleManager1.ManagerStyle
        settings.Save()
        Dim region40 As String = CLFOLDER
        Dim region90 As String = rundum
        If Not Directory.Exists(region40) Then
            Directory.CreateDirectory(region40)
        End If
        Dim gy As New IO.StreamWriter(region90)
        For Each itm As String In Me.ListBox1.Items
            gy.WriteLine(itm)
        Next
        gy.Close()
        Timer1.Stop()
        Timer3.Stop()
        My.Settings.Save()
    End Sub
    Private Sub ButtonX1_Click_1(sender As Object, e As EventArgs)
        Dim openFileDialog As OpenFileDialog = New OpenFileDialog()
        Dim openFileDialog2 As OpenFileDialog = openFileDialog
        openFileDialog2.Title = "Select something to Encrypt"
        openFileDialog2.ShowDialog()
        Me.FlatTextBox1.Text = openFileDialog.FileName
        TextBox11.Text = openFileDialog.SafeFileName
        Label30.Text = "Selected File : " + TextBox11.Text
    End Sub
    Private Sub ButtonX4_Click(sender As Object, e As EventArgs) Handles Encrypt_file.Click
        If CheckBox3.Checked = True Then
            If ComboBox1.SelectedItem = "Base64" Then
                Me.RichTextBox1.Text = Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))
            End If
            If ComboBox1.SelectedItem = "~Draven's Algorithm" Then
                Dim text4133333l As String = Convert.ToString(CryptString_1(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "ARMON64" Then
                Dim text4133333l As String = Convert.ToString(ARMON64_Encrypt(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "Atbash Cipher" Then
                Dim text4133333l As String = Convert.ToString(Atbash_Cipher(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "Vernam" Then
                Dim text4133333l As String = Convert.ToString(vernam1.x(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "RIPEMD160Hash" Then
                Dim text4133333l As String = Convert.ToString(RIPEMD160Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "SHA1Hash" Then
                Dim text4133333l As String = Convert.ToString(SHA1Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "SHA256Hash" Then
                Dim text4133333l As String = Convert.ToString(SHA256Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "SHA348Hash" Then
                Dim text4133333l As String = Convert.ToString(SHA348Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "SHA512Hash" Then
                Dim text4133333l As String = Convert.ToString(SHA512Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "MD5Hash" Then
                Dim text4133333l As String = Convert.ToString(MD5Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "EnvY'S Encryption" Then
                Dim text4133333l As String = Convert.ToString(EnvY_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text4133333l
            End If
            If ComboBox1.SelectedItem = "Compression(GZip)" Then
                Me.RichTextBox1.Text = Convert.ToBase64String(GZip(File.ReadAllBytes(Me.FlatTextBox1.Text)))
            End If
            If ComboBox1.SelectedItem = "MD5" Then
                Dim value As Object = Convert.ToBase64String(algorithms.Md5Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text, CipherMode.ECB, PaddingMode.PKCS7))
                Me.RichTextBox1.Text = Conversions.ToString(value)
            End If
            If ComboBox1.SelectedItem = "RC2" Then
                Dim text As String = Convert.ToString(algorithms.RC2Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text
            End If
            If ComboBox1.SelectedItem = "RSA" Then
                Dim text As String = Convert.ToString(RSA_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text
            End If
            If ComboBox1.SelectedItem = "ROT-13" Then
                Dim text As String = Convert.ToString(Rot13(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text
            End If
            If ComboBox1.SelectedItem = "Caesar Cipher" Then
                Dim text As String = Convert.ToString(c_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.TextBoxX10.Text))
                Me.RichTextBox1.Text = text
            End If
            If ComboBox1.SelectedItem = "AES" Then
                Dim text2 As String = Convert.ToString(algorithms.AES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text2
            End If
            If ComboBox1.SelectedItem = "DES" Then
                Dim text3 As String = Convert.ToString(algorithms.DES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text3
            End If
            If ComboBox1.SelectedItem = "Compression(Deflate)" Then
                Me.RichTextBox1.Text = Convert.ToString(algorithms.Zip_deflate(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
            End If
            If ComboBox1.SelectedItem = "RC4" Then
                Me.RichTextBox1.Text = Convert.ToBase64String(algorithms.RC4Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text))
            End If
            If ComboBox1.SelectedItem = "3DES" Then
                Me.RichTextBox1.Text = Convert.ToBase64String(cTripleDES.des.Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text)))
            End If
            If ComboBox1.SelectedItem = "Binary" Then
                Me.RichTextBox1.Text = Convert.ToString(algorithms.ConvertToBinary(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
            End If
            If ComboBox1.SelectedItem = "TripleDES" Then
                Dim text4 As String = Convert.ToString(algorithms.TripleDES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text4
            End If
            If ComboBox1.SelectedItem = "XOR" Then
                Dim text5 As String = Convert.ToString(algorithms.XOR_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text5
            End If
            If ComboBox1.SelectedItem = "Rijindael" Then
                Dim text6 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Rijndaelcrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
                Me.RichTextBox1.Text = text6
            End If
            If ComboBox1.SelectedItem = "HEX" Then
                Dim text7 As String = Convert.ToString(algorithms.String2Hex(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text7
            End If
            If ComboBox1.SelectedItem = "RSM" Then
                Me.RichTextBox1.Text = Convert.ToBase64String(algorithms.RSM(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text))
            End If
            If ComboBox1.SelectedItem = "Pr0t3" Then
                Me.RichTextBox1.Text = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.pr0t3_encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)))))
            End If
            If ComboBox1.SelectedItem = "X" Then
                Dim text100 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.x(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text)), Me.PWD.Text)))
                Me.RichTextBox1.Text = text100
            End If
            If ComboBox1.SelectedItem = "Encrypt" Then
                Dim text23 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
                Me.RichTextBox1.Text = text23
            End If
            If ComboBox1.SelectedItem = "Encryptvg" Then
                Dim text1212 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Encryptvg(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
                Me.RichTextBox1.Text = text1212
            End If
            If ComboBox1.SelectedItem = "CustomXOR" Then
                Dim text33333 As String = Convert.ToString(CustomXOR_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text33333
            End If
            If ComboBox1.SelectedItem = "Polymorphic Stairs" Then
                Dim text323333 As String = Convert.ToString(PolyCrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text323333
            End If
            If ComboBox1.SelectedItem = "Stairs" Then
                Dim text433333 As String = Convert.ToString(Crypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
                Me.RichTextBox1.Text = text433333
            End If
            If ComboBox1.SelectedItem = "Polymorphic RC4" Then
                Dim Z As New PolyRC4(PWD.Text)
                Dim text433333l As String = Convert.ToString(Z.Encrypt(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text433333l
            End If
            If ComboBox1.SelectedItem = "Line" Then
                Dim text333332 As String = Convert.ToString(converttoline(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text333332
            End If
            If ComboBox1.SelectedItem = "ATOM-128" Then
                Dim text3333322 As String = Convert.ToString(Atom128_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text3333322
            End If
            If ComboBox1.SelectedItem = "ZARA128" Then
                Dim text33333223 As String = Convert.ToString(ZARA128_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text33333223
            End If
            If ComboBox1.SelectedItem = "Custom_Line" Then
                Dim text333332233 As String = Convert.ToString(Encrypt_CustomLine(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text333332233
            End If
            If ComboBox1.SelectedItem = "GILA7" Then
                Dim text3333322333 As String = Convert.ToString(GILA7_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text3333322333
            End If
            If ComboBox1.SelectedItem = "HAZZ-15" Then
                Dim text33333223333 As String = Convert.ToString(HAZZ15_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text33333223333
            End If
            If ComboBox1.SelectedItem = "FERON-74" Then
                Dim text333332233333 As String = Convert.ToString(FERON74_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text333332233333
            End If
            If ComboBox1.SelectedItem = "ESAB-46" Then
                Dim text3333322333333 As String = Convert.ToString(ESAB46_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text3333322333333
            End If
            If ComboBox1.SelectedItem = "MEGAN-35" Then
                Dim text33333223333333 As String = Convert.ToString(MEGAN35_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text33333223333333
            End If
            If ComboBox1.SelectedItem = "ROT-13" Then
                Dim text333332233333333 As String = Convert.ToString(Rot13(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text333332233333333
            End If
            If ComboBox1.SelectedItem = "TIGO-3FX" Then
                Dim text3333322333333333 As String = Convert.ToString(TIGO3FX_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text3333322333333333
            End If
            If ComboBox1.SelectedItem = "TRIPO-5" Then
                Dim text33333223333333333 As String = Convert.ToString(TRIPO5_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                Me.RichTextBox1.Text = text33333223333333333
            End If
            If ComboBox1.SelectedItem = "ZONG-22" Then
                Dim text333332233333333333 As String = Convert.ToString(ZONG22_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
                RichTextBox1.Text = text333332233333333333
            End If
        Else
            BackgroundWorker1.RunWorkerAsync()
        End If
    End Sub
    Private Sub ButtonX5_Click(sender As Object, e As EventArgs) Handles ButtonX5.Click
        RichTextBox1.Text = StrReverse(RichTextBox1.Text)
    End Sub
    Private Sub ButtonX6_Click(sender As Object, e As EventArgs)
        RichTextBox1.Text = LCase(RichTextBox1.Text)
    End Sub
    Private Sub ButtonX1_Click(sender As Object, e As EventArgs) Handles ButtonX1.Click
        Dim folderBrowserDialog As FolderBrowserDialog = New FolderBrowserDialog()
        Dim folderBrowserDialog2 As FolderBrowserDialog = folderBrowserDialog
        If folderBrowserDialog2.ShowDialog() = DialogResult.OK Then
            Dim text As String = Conversions.ToString(Me.NumericUpDown1.Value)
            Dim text2 As String = RichTextBox1.Text
            Dim value As String = Conversions.ToString(text2.Length)
            Dim value2 As String = Conversions.ToString(Conversions.ToDouble(value) / Conversions.ToDouble(text))
            Dim text3 As String = Conversions.ToString(1)
            Dim num As Integer = 1
            Dim num2 As Integer = Conversions.ToInteger(text)
            For i As Integer = num To num2
                Dim contents As String = Strings.Mid(text2, Conversions.ToInteger(text3), Conversions.ToInteger(value2))
                File.WriteAllText(folderBrowserDialog2.SelectedPath + "\" + TextBox13.Text + "" + Conversions.ToString(i) + ".txt", contents)
                text3 += text
            Next
        End If
    End Sub
    Private Sub ButtonX6_Click_1(sender As Object, e As EventArgs) Handles ButtonX6.Click
        RichTextBox1.Text = RichTextBox1.Text.Replace(TextBoxX4.Text, TextBoxX5.Text)
    End Sub
    Private Sub ButtonX8_Click(sender As Object, e As EventArgs) Handles ButtonX8.Click
        RichTextBox1.SelectAll()
        RichTextBox1.Copy()
        MessageBox.Show("Text Copied", "Info !!!", MessageBoxButtons.OK, MessageBoxIcon.Information)
    End Sub
    Private Sub ButtonX7_Click(sender As Object, e As EventArgs) Handles ButtonX7.Click
        RichTextBox1.SelectAll()
        RichTextBox1.Clear()
        MessageBox.Show("Cleared Textbox", "Info !!!", MessageBoxButtons.OK, MessageBoxIcon.Information)
    End Sub
    Private Sub ButtonX9_Click(sender As Object, e As EventArgs) Handles ButtonX9.Click
        BackgroundWorker4.RunWorkerAsync()
    End Sub
    Private Sub ButtonX12_Click(sender As Object, e As EventArgs) Handles ButtonX12.Click
        Dim checked As Boolean = CheckBoxX1.Checked
        Dim checked2 As Boolean
        If checked Then
            checked2 = RadioButton1.Checked
            If checked2 Then
                TextBox1.Text = My.Resources.r1
            End If
            checked2 = RadioButton2.Checked
            If checked2 Then
                TextBox1.Text = My.Resources.r2
            End If
            checked2 = RadioButton3.Checked
            If checked2 Then
                TextBox1.Text = My.Resources.r3
            End If
            checked2 = RadioButton4.Checked
            If checked2 Then
                TextBox1.Text = My.Resources.r4
            End If
            checked2 = RadioButton10.Checked
            If checked2 Then
                TextBox1.Text = TextBox5.Text
            End If
        End If
    End Sub
    Private Sub ButtonX13_Click(sender As Object, e As EventArgs) Handles ButtonX13.Click
        Dim checked As Boolean = CheckBoxX2.Checked
        Dim checked2 As Boolean
        checked2 = CheckBoxX2.Checked
        If checked2 Then
            checked = RadioButton5.Checked
            If checked Then
                TextBox2.Text = My.Resources.e2
            End If
            checked2 = RadioButton6.Checked
            If checked2 Then
                TextBox2.Text = My.Resources.e3
            End If
            checked2 = RadioButton7.Checked
            If checked2 Then
                TextBox2.Text = My.Resources.e4
            End If
            checked2 = RadioButton8.Checked
            If checked2 Then
                TextBox2.Text = My.Resources.r5
            End If
            checked2 = RadioButton9.Checked
            If checked2 Then
                TextBox2.Text = TextBox3.Text
            End If
        End If
    End Sub
    Private Sub ButtonX10_Click(sender As Object, e As EventArgs) Handles ButtonX10.Click
        Dim uniqueKey As String = GetUniqueKey(NumericUpDown5.Value)
        Dim uniqueKey2 As String = GetUniqueKey(NumericUpDown6.Value)
        Dim uniqueKey3 As String = GetUniqueKey(NumericUpDown7.Value)
        Dim checked As Boolean = Me.RadioButton16.Checked
        If checked Then
            Me.TextBox1.Text = String.Concat(New String() {"Dim ", uniqueKey, " As System.Reflection.Assembly" & vbCrLf & "Dim ", uniqueKey2, " As System.Reflection.MethodInfo " & vbCrLf & "Dim ", uniqueKey3, " As Object " & vbCrLf, uniqueKey, " = System.Reflection.Assembly.Load("""")" & vbCrLf, uniqueKey2, " = ", uniqueKey, ".EntryPoint" & vbCrLf, uniqueKey3, " = ", uniqueKey, ".CreateInstance(", uniqueKey2, ".Name)" & vbCrLf, uniqueKey2, ".Invoke(", uniqueKey3, ", Nothing)"})
        End If
        checked = Me.RadioButton15.Checked
        If checked Then
            Me.TextBox1.Text = String.Concat(New String() {"Dim ", uniqueKey, " As Object = Reflection.Assembly.Load("""")" & vbCrLf, uniqueKey, ".EntryPoint.Invoke(Nothing, Nothing)"})
        End If
        checked = Me.RadioButton17.Checked
        If checked Then
            Me.TextBox1.Text = String.Concat(New String() {"Sub main(ByVal ", uniqueKey, " As String())" & vbCrLf & "Dim ", uniqueKey2, " As Object() = New Object(-1) {}" & vbCrLf & "Dim ", uniqueKey3, " As System.Reflection.Assembly = AppDomain.CurrentDomain.Load("""")" & vbCrLf & "If ", uniqueKey3, ".EntryPoint.GetParameters().Length > 0 Then" & vbCrLf, uniqueKey2, " = New Object() {", uniqueKey, "}" & vbCrLf & "End If" & vbCrLf, uniqueKey3, ".EntryPoint.Invoke(Nothing, ", uniqueKey2, ")" & vbCrLf & "End Sub"})
        End If
    End Sub
    Private Sub ButtonX4_Click_1(sender As Object, e As EventArgs) Handles ButtonX4.Click
        POPULATE()
    End Sub
    Private Sub ButtonX11_Click(sender As Object, e As EventArgs) Handles ButtonX11.Click
        Clipboard.Clear()
    End Sub
    Private Sub ButtonX14_Click(sender As Object, e As EventArgs) Handles ButtonX14.Click
        Clipboard.SetText(TextBox7.Text)
    End Sub
    Private Sub ButtonX15_Click(sender As Object, e As EventArgs) Handles ButtonX15.Click
        POPULATE2()
    End Sub
    Private Sub TextBoxX9_KeyPress(sender As Object, e As KeyPressEventArgs)
        If Not Char.IsControl(e.KeyChar) AndAlso Not Char.IsDigit(e.KeyChar) AndAlso (e.KeyChar <> "."c) Then
            e.Handled = True
        End If
        If (e.KeyChar = "."c) AndAlso (TryCast(sender, TextBox).Text.IndexOf("."c) > -1) Then
            e.Handled = True
        End If
    End Sub
    Private Sub TextBoxX10_KeyPress(sender As Object, e As KeyPressEventArgs)
        If Not Char.IsControl(e.KeyChar) AndAlso Not Char.IsDigit(e.KeyChar) AndAlso (e.KeyChar <> "."c) Then
            e.Handled = True
        End If
        If (e.KeyChar = "."c) AndAlso (TryCast(sender, TextBox).Text.IndexOf("."c) > -1) Then
            e.Handled = True
        End If
    End Sub
    Private Sub ToolStripButton1_Click(sender As Object, e As EventArgs) Handles ToolStripButton1.Click
        Dim openFileDialog As OpenFileDialog = New OpenFileDialog()
        Dim openFileDialog2 As OpenFileDialog = openFileDialog
        openFileDialog2.Title = "Select something to Encrypt"
        openFileDialog2.ShowDialog()
        Me.FlatTextBox1.Text = openFileDialog.FileName
        TextBox11.Text = openFileDialog.SafeFileName
        Label30.Text = "Selected File : " + TextBox11.Text
    End Sub
    Private Sub TextBoxX11_KeyPress(sender As Object, e As KeyPressEventArgs)
        If Not Char.IsControl(e.KeyChar) AndAlso Not Char.IsDigit(e.KeyChar) AndAlso (e.KeyChar <> "."c) Then
            e.Handled = True
        End If
        If (e.KeyChar = "."c) AndAlso (TryCast(sender, TextBox).Text.IndexOf("."c) > -1) Then
            e.Handled = True
        End If
    End Sub
    Private Sub ButtonX17_Click(sender As Object, e As EventArgs) Handles ButtonX17.Click
        ListBox1.Items.Add(TextBox35.Text)
    End Sub
    Private Sub RemoveToolStripMenuItem_Click(sender As Object, e As EventArgs)
        Dim dirt As String = ListBox1.SelectedItem
        ListBox1.Items.Remove(dirt)
    End Sub
    Private Sub RichTextBox1_DoubleClick(sender As Object, e As EventArgs) Handles RichTextBox1.DoubleClick
        RichTextBox1.SelectAll()
    End Sub
    Private Sub ButtonX64_Click(sender As Object, e As EventArgs) Handles ButtonX64.Click
        BackgroundWorker6.RunWorkerAsync()
    End Sub
#Region "BACKGROUND WORKERS"
    Private Sub BackgroundWorker1_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker1.DoWork
        If ComboBox1.SelectedItem = "Base64" Then
            Me.RichTextBox1.Text = Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))
        End If
        If ComboBox1.SelectedItem = "~Draven's Algorithm" Then
            Dim text4133333l As String = Convert.ToString(CryptString_1(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "ARMON64" Then
            Dim text4133333l As String = Convert.ToString(ARMON64_Encrypt(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "Atbash Cipher" Then
            Dim text4133333l As String = Convert.ToString(Atbash_Cipher(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "Vernam" Then
            Dim text4133333l As String = Convert.ToString(vernam1.x(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "RIPEMD160Hash" Then
            Dim text4133333l As String = Convert.ToString(RIPEMD160Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "SHA1Hash" Then
            Dim text4133333l As String = Convert.ToString(SHA1Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "SHA256Hash" Then
            Dim text4133333l As String = Convert.ToString(SHA256Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "SHA348Hash" Then
            Dim text4133333l As String = Convert.ToString(SHA348Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "SHA512Hash" Then
            Dim text4133333l As String = Convert.ToString(SHA512Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "MD5Hash" Then
            Dim text4133333l As String = Convert.ToString(MD5Hash(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "EnvY'S Encryption" Then
            Dim text4133333l As String = Convert.ToString(EnvY_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text4133333l
        End If
        If ComboBox1.SelectedItem = "Compression(GZip)" Then
            Me.RichTextBox1.Text = Convert.ToBase64String(GZip(File.ReadAllBytes(Me.FlatTextBox1.Text)))
        End If
        If ComboBox1.SelectedItem = "MD5" Then
            Dim value As Object = Convert.ToBase64String(algorithms.Md5Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text, CipherMode.ECB, PaddingMode.PKCS7))
            Me.RichTextBox1.Text = Conversions.ToString(value)
        End If
        If ComboBox1.SelectedItem = "RC2" Then
            Dim text As String = Convert.ToString(algorithms.RC2Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text
        End If
        If ComboBox1.SelectedItem = "RSA" Then
            Dim text As String = Convert.ToString(RSA_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text
        End If
        If ComboBox1.SelectedItem = "ROT-13" Then
            Dim text As String = Convert.ToString(Rot13(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text
        End If
        If ComboBox1.SelectedItem = "Caesar Cipher" Then
            Dim text As String = Convert.ToString(c_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.TextBoxX10.Text))
            Me.RichTextBox1.Text = text
        End If
        If ComboBox1.SelectedItem = "AES" Then
            Dim text2 As String = Convert.ToString(algorithms.AES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text2
        End If
        If ComboBox1.SelectedItem = "DES" Then
            Dim text3 As String = Convert.ToString(algorithms.DES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text3
        End If
        If ComboBox1.SelectedItem = "Compression(Deflate)" Then
            Me.RichTextBox1.Text = Convert.ToString(algorithms.Zip_deflate(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
        End If
        If ComboBox1.SelectedItem = "RC4" Then
            Me.RichTextBox1.Text = Convert.ToBase64String(algorithms.RC4Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text))
        End If
        If ComboBox1.SelectedItem = "3DES" Then
            Me.RichTextBox1.Text = Convert.ToBase64String(cTripleDES.des.Encrypt(File.ReadAllBytes(Me.FlatTextBox1.Text)))
        End If
        If ComboBox1.SelectedItem = "Binary" Then
            Me.RichTextBox1.Text = Convert.ToString(algorithms.ConvertToBinary(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
        End If
        If ComboBox1.SelectedItem = "TripleDES" Then
            Dim text4 As String = Convert.ToString(algorithms.TripleDES_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text4
        End If
        If ComboBox1.SelectedItem = "XOR" Then
            Dim text5 As String = Convert.ToString(algorithms.XOR_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text5
        End If
        If ComboBox1.SelectedItem = "Rijindael" Then
            Dim text6 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Rijndaelcrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
            Me.RichTextBox1.Text = text6
        End If
        If ComboBox1.SelectedItem = "HEX" Then
            Dim text7 As String = Convert.ToString(algorithms.String2Hex(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text7
        End If
        If ComboBox1.SelectedItem = "RSM" Then
            Me.RichTextBox1.Text = Convert.ToBase64String(algorithms.RSM(File.ReadAllBytes(Me.FlatTextBox1.Text), Me.PWD.Text))
        End If
        If ComboBox1.SelectedItem = "Pr0t3" Then
            Me.RichTextBox1.Text = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.pr0t3_encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)))))
        End If
        If ComboBox1.SelectedItem = "X" Then
            Dim text100 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.x(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text)), Me.PWD.Text)))
            Me.RichTextBox1.Text = text100
        End If
        If ComboBox1.SelectedItem = "Encrypt" Then
            Dim text23 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
            Me.RichTextBox1.Text = text23
        End If
        If ComboBox1.SelectedItem = "Encryptvg" Then
            Dim text1212 As String = Convert.ToString(RuntimeHelpers.GetObjectValue(algorithms.Encryptvg(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text)))
            Me.RichTextBox1.Text = text1212
        End If
        If ComboBox1.SelectedItem = "CustomXOR" Then
            Dim text33333 As String = Convert.ToString(CustomXOR_Encrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text33333
        End If
        If ComboBox1.SelectedItem = "Polymorphic Stairs" Then
            Dim text323333 As String = Convert.ToString(PolyCrypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text323333
        End If
        If ComboBox1.SelectedItem = "Stairs" Then
            Dim text433333 As String = Convert.ToString(Crypt(Convert.ToBase64String(File.ReadAllBytes(Me.FlatTextBox1.Text)), Me.PWD.Text))
            Me.RichTextBox1.Text = text433333
        End If
        If ComboBox1.SelectedItem = "Polymorphic RC4" Then
            Dim Z As New PolyRC4(PWD.Text)
            Dim text433333l As String = Convert.ToString(Z.Encrypt(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text433333l
        End If
        If ComboBox1.SelectedItem = "Line" Then
            Dim text333332 As String = Convert.ToString(converttoline(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text333332
        End If
        If ComboBox1.SelectedItem = "ATOM-128" Then
            Dim text3333322 As String = Convert.ToString(Atom128_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text3333322
        End If
        If ComboBox1.SelectedItem = "ZARA128" Then
            Dim text33333223 As String = Convert.ToString(ZARA128_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text33333223
        End If
        If ComboBox1.SelectedItem = "Custom_Line" Then
            Dim text333332233 As String = Convert.ToString(Encrypt_CustomLine(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text333332233
        End If
        If ComboBox1.SelectedItem = "GILA7" Then
            Dim text3333322333 As String = Convert.ToString(GILA7_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text3333322333
        End If
        If ComboBox1.SelectedItem = "HAZZ-15" Then
            Dim text33333223333 As String = Convert.ToString(HAZZ15_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text33333223333
        End If
        If ComboBox1.SelectedItem = "FERON-74" Then
            Dim text333332233333 As String = Convert.ToString(FERON74_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text333332233333
        End If
        If ComboBox1.SelectedItem = "ESAB-46" Then
            Dim text3333322333333 As String = Convert.ToString(ESAB46_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text3333322333333
        End If
        If ComboBox1.SelectedItem = "MEGAN-35" Then
            Dim text33333223333333 As String = Convert.ToString(MEGAN35_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text33333223333333
        End If
        If ComboBox1.SelectedItem = "ROT-13" Then
            Dim text333332233333333 As String = Convert.ToString(Rot13(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text333332233333333
        End If
        If ComboBox1.SelectedItem = "TIGO-3FX" Then
            Dim text3333322333333333 As String = Convert.ToString(TIGO3FX_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text3333322333333333
        End If
        If ComboBox1.SelectedItem = "TRIPO-5" Then
            Dim text33333223333333333 As String = Convert.ToString(TRIPO5_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            Me.RichTextBox1.Text = text33333223333333333
        End If
        If ComboBox1.SelectedItem = "ZONG-22" Then
            Dim text333332233333333333 As String = Convert.ToString(ZONG22_Encode(Convert.ToBase64String(File.ReadAllBytes(FlatTextBox1.Text))))
            RichTextBox1.Text = text333332233333333333
        End If
    End Sub
    Private Sub BackgroundWorker2_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker2.DoWork
        Try
            If ReactorComboBox1.SelectedItem = "~Draven's Algorithm" Then
                Logintextbox1.Text = CryptString_1(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "3DES" Then
                Logintextbox1.Text = EncryptString(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "AES" Then
                Logintextbox1.Text = AES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Atbash Cipher" Then
                Logintextbox1.Text = Atbash_Cipher(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ATOM-128" Then
                Logintextbox1.Text = Atom128_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Base64" Then
                Logintextbox1.Text = BASE64_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Binary" Then
                Logintextbox1.Text = ConvertToBinary(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Caesar Cipher" Then
                Logintextbox1.Text = c_Encrypt(Logintextbox1.Text, TextBoxX11.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Compression(Deflate)" Then
                Logintextbox1.Text = Zip_deflate(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Compression(GZip)" Then
                Logintextbox1.Text = Zip_G(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Custom_Line" Then
                Logintextbox1.Text = Encrypt_CustomLine(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "CustomXOR" Then
                Logintextbox1.Text = CustomXOR_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "DES" Then
                Logintextbox1.Text = DES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "EnvY'S Encryption" Then
                Logintextbox1.Text = EnvY_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ESAB-46" Then
                Logintextbox1.Text = ESAB46_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "FERON-74" Then
                Logintextbox1.Text = FERON74_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "GILA7" Then
                Logintextbox1.Text = GILA7_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "HAZZ-15" Then
                Logintextbox1.Text = HAZZ15_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "HEX" Then
                Logintextbox1.Text = String2Hex(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "LowerCase ( Can't Decrypt )" Then
                Logintextbox1.Text = Logintextbox1.Text.ToLower
            ElseIf ReactorComboBox1.SelectedItem = "MD5Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = MD5Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "MEGAN-35" Then
                Logintextbox1.Text = MEGAN35_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Morse Code" Then
                Logintextbox1.Text = String.Join("/", Array.ConvertAll(Logintextbox1.Text.ToArray, Function(c) If(translation.Keys.Contains(c.ToString.ToUpper), translation(c.ToString.ToUpper), c.ToString)))
                Logintextbox1.Refresh()
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic RC4" Then
                Dim x As New PolyRC4(ReactorTextBox1.Text)
                Logintextbox1.Text = x.Encrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic Stairs" Then
                Logintextbox1.Text = PolyCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Pr0t3" Then
                Logintextbox1.Text = pr0t3_encrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RC2" Then
                Logintextbox1.Text = RC2Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RC4" Then
                Logintextbox1.Text = rc4(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Reverse" Then
                Logintextbox1.Text = ReverseString(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Rinjandel" Then
                Logintextbox1.Text = Rijndaelcrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RIPEMD160Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = RIPEMD160Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ROT-13" Then
                Logintextbox1.Text = Rot13(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RSA" Then
                Logintextbox1.Text = RSA_Encrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "SHA1Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = SHA1Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "SHA256Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = SHA256Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "SHA348Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = SHA348Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "SHA512Hash ( Can't Decrypt )" Then
                Logintextbox1.Text = SHA512Hash(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Stairs" Then
                Logintextbox1.Text = Crypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "TIGO-3FX" Then
                Logintextbox1.Text = TIGO3FX_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "TripleDES" Then
                Logintextbox1.Text = TripleDES_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "TRIPO-5" Then
                Logintextbox1.Text = TRIPO5_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "UpperCase ( Can't Decrypt )" Then
                Logintextbox1.Text = Logintextbox1.Text.ToUpper
            ElseIf ReactorComboBox1.SelectedItem = "Vernam" Then
                Logintextbox1.Text = Convert.ToString(vernam1.x(Logintextbox1.Text, ReactorTextBox1.Text))
            ElseIf ReactorComboBox1.SelectedItem = "Vigenere" Then
                Logintextbox1.Text = Convert.ToString(Vigenere_Cipher(Logintextbox1.Text, ReactorTextBox1.Text, True))
            ElseIf ReactorComboBox1.SelectedItem = "XOR" Then
                Logintextbox1.Text = XOR_Encrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ZARA128" Then
                Logintextbox1.Text = ZARA128_Encode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ZONG-22" Then
                Logintextbox1.Text = ZONG22_Encode(Logintextbox1.Text)
            End If
        Catch Ex As Exception
            MsgBox(Err.Description)
        End Try
    End Sub
    Private Sub BackgroundWorker3_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker3.DoWork
        Try
            If ReactorComboBox1.SelectedItem = "~Draven's Algorithm" Then
                Logintextbox1.Text = DecryptString_1(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "3DES" Then
                Logintextbox1.Text = DecryptString(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "AES" Then
                Logintextbox1.Text = AES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Atbash Cipher" Then
                Logintextbox1.Text = Atbash_Cipher(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ATOM-128" Then
                Dim cost As String
                cost = Atom128_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "Base64" Then
                Logintextbox1.Text = BASE64_Decode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Binary" Then
                Logintextbox1.Text = ConvertToAscii(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Caesar Cipher" Then
                Logintextbox1.Text = c_Decrypt(Logintextbox1.Text, TextBoxX11.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Compression(Deflate)" Then
                Logintextbox1.Text = UnZip_deflate(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Compression(GZip)" Then
                Logintextbox1.Text = UnZip_G(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Custom_Line" Then
                Logintextbox1.Text = Decrypt_CustomLine(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "CustomXOR" Then
                Logintextbox1.Text = CustomXOR_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "DES" Then
                Logintextbox1.Text = DES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "EnvY'S Encryption" Then
                Logintextbox1.Text = EnvY_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ESAB-46" Then
                Dim cost As String
                cost = ESAB46_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "FERON-74" Then
                Dim cost As String
                cost = FERON74_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "GILA7" Then
                Dim cost As String
                cost = GILA7_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "HAZZ-15" Then
                Dim cost As String
                cost = HAZZ15_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "HEX" Then
                Logintextbox1.Text = Hex2String(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "MEGAN-35" Then
                Dim cost As String
                cost = MEGAN35_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "Morse Code" Then
                Logintextbox1.Text = String.Concat(Array.ConvertAll(Logintextbox1.Text.Split("/"c), Function(s) If(translation.Values.Contains(s), translation.First(Function(kvp) kvp.Value = s).Key, s)))
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic RC4" Then
                Dim Y As New PolyRC4(ReactorTextBox1.Text)
                Logintextbox1.Text = Y.Decrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Polymorphic Stairs" Then
                Logintextbox1.Text = PolyDeCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Pr0t3" Then
                Logintextbox1.Text = pr0t3_decrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RC2" Then
                Logintextbox1.Text = RC2Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RC4" Then
                Logintextbox1.Text = rc4(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Reverse" Then
                Logintextbox1.Text = ReverseString(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Rinjandel" Then
                Logintextbox1.Text = RijndaelDecrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ROT-13" Then
                Logintextbox1.Text = Rot13(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "RSA" Then
                Logintextbox1.Text = RSA_Decrypt(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Stairs" Then
                Logintextbox1.Text = DeCrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "TIGO-3FX" Then
                Dim cost As String
                cost = TIGO3FX_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "TripleDES" Then
                Logintextbox1.Text = TripleDES_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "TRIPO-5" Then
                Dim cost As String
                cost = TRIPO5_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            ElseIf ReactorComboBox1.SelectedItem = "Vernam" Then
                Logintextbox1.Text = Vernam(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "Vigenere" Then
                Logintextbox1.Text = Convert.ToString(Vigenere_Cipher(Logintextbox1.Text, ReactorTextBox1.Text, False))
            ElseIf ReactorComboBox1.SelectedItem = "XOR" Then
                Logintextbox1.Text = XOR_Decrypt(Logintextbox1.Text, ReactorTextBox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ZARA128" Then
                Logintextbox1.Text = ZARA128_Decode(Logintextbox1.Text)
            ElseIf ReactorComboBox1.SelectedItem = "ZONG-22" Then
                Dim cost As String
                cost = ZONG22_Decode(Logintextbox1.Text)
                cost = Replace(cost, "%20", " ")
                cost = Replace(cost, "%3F", "?")
                cost = Replace(cost, "%2C", ",")
                Logintextbox1.Text = cost
            End If
        Catch ex As Exception
            MsgBox(Err.Description)
        End Try
    End Sub
    Private Sub BackgroundWorker4_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker4.DoWork
        If ComboBox2.SelectedItem = "Rijindael" Then
            TextBoxX6.Text = My.Resources.Rijndael___Decrypt__
        End If
        If ComboBox2.SelectedItem = "3DES" Then
            TextBoxX6.Text = My.Resources._3DES___Decrypt__
        End If
        If ComboBox2.SelectedItem = "AES" Then
            TextBoxX6.Text = My.Resources.AES_Decrypt
        End If
        If ComboBox2.SelectedItem = "~Draven's Algorithm" Then
            TextBoxX6.Text = My.Resources.DecryptString_1___Draven_Decrypt__
        End If
        If ComboBox2.SelectedItem = "EnvY'S Encryption" Then
            TextBoxX6.Text = My.Resources.EnvY_S_Encryption___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Base64" Then
            TextBoxX6.Text = My.Resources.BASE64_Decode
        End If
        If ComboBox2.SelectedItem = "XOR" Then
            TextBoxX6.Text = My.Resources.XOR_Decrypt
        End If
        If ComboBox2.SelectedItem = "TripleDES" Then
            TextBoxX6.Text = My.Resources.TripleDES_Decrypt
        End If
        If ComboBox2.SelectedItem = "RSM" Then
            TextBoxX6.Text = My.Resources.RSM___Decrypt__
        End If
        If ComboBox2.SelectedItem = "RC4" Then
            TextBoxX6.Text = My.Resources.RC4___Decrypt__
        End If
        If ComboBox2.SelectedItem = "RC2" Then
            TextBoxX6.Text = My.Resources.RC2___Decrypt__
        End If
        If ComboBox2.SelectedItem = "DES" Then
            TextBoxX6.Text = My.Resources.DES_Decrypt
        End If
        If ComboBox2.SelectedItem = "Compression(Deflate)" Then
            TextBoxX6.Text = My.Resources.UnZip_deflate___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Compression(GZip)" Then
            TextBoxX6.Text = My.Resources.UnZip_G____Decrypt__
        End If
        If ComboBox2.SelectedItem = "MD5" Then
            TextBoxX6.Text = My.Resources.MD5___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Pr0t3" Then
            TextBoxX6.Text = My.Resources.pr0t3_decrypt
        End If
        If ComboBox2.SelectedItem = "Vernam" Then
            TextBoxX6.Text = My.Resources.Vernam___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Vigenere" Then
            TextBoxX6.Text = My.Resources.VeginereDecrypt
        End If
        If ComboBox2.SelectedItem = "Polymorphic Stairs" Then
            TextBoxX6.Text = My.Resources.Polymorphic_Stairs___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Stairs" Then
            TextBoxX6.Text = My.Resources.Stairs___Decrypt__
        End If
        If ComboBox2.SelectedItem = "Hex Decrypt" Then
            TextBoxX6.Text = My.Resources.Decrypt_Hex
        End If
        If ComboBox2.SelectedItem = "Decrypt Binary" Then
            TextBoxX6.Text = My.Resources.Decrypt_Binary
        End If
        If ComboBox2.SelectedItem = "CustomXOR" Then
            TextBoxX6.Text = My.Resources.CustomXOR_Decrypt
        End If
        If ComboBox2.SelectedItem = "ATOM-128" Then
            TextBoxX6.Text = My.Resources.Atom128_Decode
        End If
        If ComboBox2.SelectedItem = "ZARA128" Then
            TextBoxX6.Text = My.Resources.ZARA128_Decode
        End If
        If ComboBox2.SelectedItem = "Custom_Line" Then
            TextBoxX6.Text = My.Resources.Decrypt_CustomLine
        End If
        If ComboBox2.SelectedItem = "GILA7" Then
            TextBoxX6.Text = My.Resources.GILA7_Decode
        End If
        If ComboBox2.SelectedItem = "HAZZ-15" Then
            TextBoxX6.Text = My.Resources.HAZZ15_Decode
        End If
        If ComboBox2.SelectedItem = "FERON-74" Then
            TextBoxX6.Text = My.Resources.FERON74_Decode
        End If
        If ComboBox2.SelectedItem = "ESAB-46" Then
            TextBoxX6.Text = My.Resources.ESAB46_Decode
        End If
        If ComboBox2.SelectedItem = "MEGAN-35" Then
            TextBoxX6.Text = My.Resources.MEGAN35_Decode
        End If
        If ComboBox2.SelectedItem = "TIGO-3FX" Then
            TextBoxX6.Text = My.Resources.TIGO3FX_Decode
        End If
        If ComboBox2.SelectedItem = "TRIPO-5" Then
            TextBoxX6.Text = My.Resources.TRIPO5_Decode
        End If
        If ComboBox2.SelectedItem = "ZONG-22" Then
            TextBoxX6.Text = My.Resources.ZONG22_Decode
        End If
        If ComboBox2.SelectedItem = "Caesar Cipher" Then
            TextBoxX6.Text = My.Resources.Caesar_Cipher___Decrypt__
        End If
        If ComboBox2.SelectedItem = "ARMON64" Then
            TextBoxX6.Text = My.Resources.ARMON64_Decrypt
        End If
        If ComboBox2.SelectedItem = "AER256" Then
            TextBoxX6.Text = My.Resources.AER256_Encrypt
        End If
        If ComboBox2.SelectedItem = "EZIP64" Then
            TextBoxX6.Text = My.Resources.EZIP64_Encrypt
        End If
        If ComboBox2.SelectedItem = "OKTO3" Then
            TextBoxX6.Text = My.Resources.OKTO3_Decrypt
        End If
    End Sub
    Private Sub BackgroundWorker5_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker5.DoWork
        translation.Add("A", "*-")
        translation.Add("B", "-***")
        translation.Add("C", "-*-*")
        translation.Add("D", "-**")
        translation.Add("E", "*")
        translation.Add("F", "**-*")
        translation.Add("G", "--*")
        translation.Add("H", "****")
        translation.Add("I", "**")
        translation.Add("J", "*---")
        translation.Add("K", "-*-")
        translation.Add("L", "*-**")
        translation.Add("M", "--")
        translation.Add("N", "-*")
        translation.Add("O", "---")
        translation.Add("P", "*--*")
        translation.Add("Q", "--*-")
        translation.Add("R", "*-*")
        translation.Add("S", "***")
        translation.Add("T", "-")
        translation.Add("U", "**-")
        translation.Add("V", "***-")
        translation.Add("W", "*--")
        translation.Add("X", "-**-")
        translation.Add("Y", "-*--")
        translation.Add("Z", "--**")
        translation.Add("1", "*----")
        translation.Add("2", "**---")
        translation.Add("3", "***--")
        translation.Add("4", "****-")
        translation.Add("5", "*****")
        translation.Add("6", "-****")
        translation.Add("7", "--***")
        translation.Add("8", "---**")
        translation.Add("9", "----*")
        translation.Add("0", "-----")
        translation.Add(".", "*-*-*-")
        translation.Add(",", "--**--")
        translation.Add("?", "**--**")
        translation.Add("'", "*----*")
        translation.Add("!", "-*-*--")
        translation.Add("/", "-**-*")
        translation.Add("(", "-*--*")
        translation.Add(")", "-*--*-")
        translation.Add("&", "*-***")
        translation.Add(":", "---***")
        translation.Add(";", "-*-*-*")
        translation.Add("=", "-***-")
        translation.Add("+", "*-*-*")
        translation.Add("-", "-****-")
        translation.Add("_", "**--*-")
        translation.Add("""", "*-**-*")
        translation.Add("$", "***-**-")
        translation.Add("@", "*--*-*")
    End Sub
    Private Sub BackgroundWorker6_DoWork(sender As Object, e As System.ComponentModel.DoWorkEventArgs) Handles BackgroundWorker6.DoWork
        If ComboBox3.SelectedItem = "Rijindael" Then
            TextBox38.Text = My.Resources.Rijndaelcrypt
        End If
        If ComboBox3.SelectedItem = "3DES" Then
            TextBox38.Text = My.Resources._3DES_ENCRYPT
        End If
        If ComboBox3.SelectedItem = "AES" Then
            TextBox38.Text = My.Resources.AES_Encrypt
        End If
        If ComboBox3.SelectedItem = "~Draven's Algorithm" Then
            TextBox38.Text = My.Resources.CryptString_1___Draven__
        End If
        If ComboBox3.SelectedItem = "EnvY'S Encryption" Then
            TextBox38.Text = My.Resources.EnvY_Encrypt
        End If
        If ComboBox3.SelectedItem = "Base64" Then
            TextBox38.Text = My.Resources.BASE64_Encode
        End If
        If ComboBox3.SelectedItem = "XOR" Then
            TextBox38.Text = My.Resources.XOR_Encrypt
        End If
        If ComboBox3.SelectedItem = "TripleDES" Then
            TextBox38.Text = My.Resources.TripleDES_Encrypt
        End If
        If ComboBox3.SelectedItem = "RSM" Then
            TextBox38.Text = My.Resources.RSMEncrypt
        End If
        If ComboBox3.SelectedItem = "RC4" Then
            TextBox38.Text = My.Resources.RC4_ENCRYPT
        End If
        If ComboBox3.SelectedItem = "RC2" Then
            TextBox38.Text = My.Resources.RC2Encrypt
        End If
        If ComboBox3.SelectedItem = "DES" Then
            TextBox38.Text = My.Resources.DES_Encrypt
        End If
        If ComboBox3.SelectedItem = "Compression(Deflate)" Then
            TextBox38.Text = My.Resources.Zip_deflate_ENCRYPT
        End If
        If ComboBox3.SelectedItem = "Compression(GZip)" Then
            TextBox38.Text = My.Resources.Zip_G_ENCRYPT
        End If
        If ComboBox3.SelectedItem = "MD5" Then
            TextBox38.Text = My.Resources.MD5_Encrypt
        End If
        If ComboBox3.SelectedItem = "Pr0t3" Then
            TextBox38.Text = My.Resources.pr0t3_encrypt
        End If
        If ComboBox3.SelectedItem = "Vernam" Then
            TextBox38.Text = My.Resources.vernam_encrypt
        End If
        If ComboBox3.SelectedItem = "Vigenere" Then
            TextBox38.Text = My.Resources.Vigenere_encrypt
        End If
        If ComboBox3.SelectedItem = "Polymorphic Stairs" Then
            TextBox38.Text = My.Resources.Polymorphic_Stairs___Encrypt__
        End If
        If ComboBox3.SelectedItem = "Stairs" Then
            TextBox38.Text = My.Resources.Stairs___Encrypt__
        End If
        If ComboBox3.SelectedItem = "Hex" Then
            TextBox38.Text = My.Resources.HEX_ENCRYPT
        End If
        If ComboBox3.SelectedItem = "Binary" Then
            TextBox38.Text = My.Resources.ConvertToBinary
        End If
        If ComboBox3.SelectedItem = "CustomXOR" Then
            TextBox38.Text = My.Resources.CustomXOR_Encrypt
        End If
        If ComboBox3.SelectedItem = "ATOM-128" Then
            TextBox38.Text = My.Resources.Atom128_Encode
        End If
        If ComboBox3.SelectedItem = "ZARA128" Then
            TextBox38.Text = My.Resources.ZARA128_Encode
        End If
        If ComboBox3.SelectedItem = "Custom_Line" Then
            TextBox38.Text = My.Resources.Encrypt_CustomLine
        End If
        If ComboBox3.SelectedItem = "GILA7" Then
            TextBox38.Text = My.Resources.GILA7_Encode
        End If
        If ComboBox3.SelectedItem = "HAZZ-15" Then
            TextBox38.Text = My.Resources.HAZZ15_Encode
        End If
        If ComboBox3.SelectedItem = "FERON-74" Then
            TextBox38.Text = My.Resources.FERON74_Encode
        End If
        If ComboBox3.SelectedItem = "ESAB-46" Then
            TextBox38.Text = My.Resources.ESAB46_Encode
        End If
        If ComboBox3.SelectedItem = "MEGAN-35" Then
            TextBox38.Text = My.Resources.MEGAN35_Encode
        End If
        If ComboBox3.SelectedItem = "TIGO-3FX" Then
            TextBox38.Text = My.Resources.TIGO3FX_Encode
        End If
        If ComboBox3.SelectedItem = "TRIPO-5" Then
            TextBox38.Text = My.Resources.TRIPO5_Encode
        End If
        If ComboBox3.SelectedItem = "ZONG-22" Then
            TextBox38.Text = My.Resources.ZONG22_Encode
        End If
        If ComboBox3.SelectedItem = "Caesar Cipher" Then
            TextBox38.Text = My.Resources.Caesar_Cipher___Encrypt__
        End If
        If ComboBox3.SelectedItem = "RIPEMD160Hash" Then
            TextBox38.Text = My.Resources.RIPEMD160Hash
        End If
        If ComboBox3.SelectedItem = "MD5Hash" Then
            TextBox38.Text = My.Resources.MD5Hash
        End If
        If ComboBox3.SelectedItem = "SHA1Hash" Then
            TextBox38.Text = My.Resources.SHA1Hash
        End If
        If ComboBox3.SelectedItem = "SHA256Hash" Then
            TextBox38.Text = My.Resources.SHA256Hash
        End If
        If ComboBox3.SelectedItem = "SHA348Hash" Then
            TextBox38.Text = My.Resources.SHA348Hash
        End If
        If ComboBox3.SelectedItem = "SHA512Hash" Then
            TextBox38.Text = My.Resources.SHA512Hash
        End If
        If ComboBox3.SelectedItem = "MACTripleDES" Then
            TextBox38.Text = My.Resources.MACTripleDES
        End If
        If ComboBox3.SelectedItem = "HMACSHA512" Then
            TextBox38.Text = My.Resources.HMACSHA512
        End If
        If ComboBox3.SelectedItem = "HMACSHA384" Then
            TextBox38.Text = My.Resources.HMACSHA384
        End If
        If ComboBox3.SelectedItem = "HMACSHA256" Then
            TextBox38.Text = My.Resources.HMACSHA256
        End If
        If ComboBox3.SelectedItem = "HMACSHA1" Then
            TextBox38.Text = My.Resources.HMACSHA1
        End If
        If ComboBox3.SelectedItem = "HMACRIPEMD160" Then
            TextBox38.Text = My.Resources.HMACRIPEMD160
        End If
        If ComboBox3.SelectedItem = "HMACMD5" Then
            TextBox38.Text = My.Resources.HMACMD5
        End If
        If ComboBox3.SelectedItem = "ARMON64" Then
            TextBox38.Text = My.Resources.ARMON64_Encrypt
        End If
        If ComboBox3.SelectedItem = "AER256" Then
            TextBox38.Text = My.Resources.AER256_Encrypt
        End If
        If ComboBox3.SelectedItem = "EZIP64" Then
            TextBox38.Text = My.Resources.EZIP64_Encrypt
        End If
        If ComboBox3.SelectedItem = "OKTO3" Then
            TextBox38.Text = My.Resources.OKTO3_Encrypt
        End If
    End Sub
#End Region
#Region "GENS"
#Region "GEN 1"
    Private Sub TextBoxX2_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX2.MouseMove
        If ListBox2.SelectedItem = Nothing Then
            TextBoxX2.Text = RNP()
        End If
        If ListBox2.SelectedItem = "Normal" Then
            TextBoxX2.Text = RNP()
        End If
        If ListBox2.SelectedItem = "Replace" Then
            Dim XO = TextBox41.Text
            Dim xttTTT = TextBox42.Text
            TextBoxX2.Text = RNP().Replace(XO, xttTTT)
        End If
        If ListBox2.SelectedItem = "Reverse" Then
            TextBoxX2.Text = Strings.StrReverse(RNP())
        End If
        If ListBox2.SelectedItem = "Lowercase" Then
            TextBoxX2.Text = Strings.LCase(RNP())
        End If
        If ListBox2.SelectedItem = "Uppercase" Then
            TextBoxX2.Text = Strings.UCase(RNP())
        End If


    End Sub
#End Region
#Region "GEN 2"
    Private Sub TextBoxX3_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX3.MouseMove
        If ListBox3.SelectedItem = Nothing Then
            TextBoxX3.Text = RNM()
        End If
        If ListBox3.SelectedItem = "Normal" Then
            TextBoxX3.Text = RNM()
        End If
        If ListBox3.SelectedItem = "Replace" Then
            Dim XO = TextBox44.Text
            Dim xttTTT = TextBox43.Text
            TextBoxX3.Text = RNM().Replace(XO, xttTTT)
        End If
        If ListBox3.SelectedItem = "Reverse" Then
            TextBoxX3.Text = Strings.StrReverse(RNM())
        End If
        If ListBox3.SelectedItem = "Lowercase" Then
            TextBoxX3.Text = Strings.LCase(RNM())
        End If
        If ListBox3.SelectedItem = "Uppercase" Then
            TextBoxX3.Text = Strings.UCase(RNM())
        End If
    End Sub
#End Region
#Region "GEN 3"
    Private Sub TextBoxX12_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX12.MouseMove
        If ListBox4.SelectedItem = Nothing Then
            TextBoxX12.Text = GenerateRandomString(NumericUpDown4.Value)
        End If
        If ListBox4.SelectedItem = "Normal" Then
            TextBoxX12.Text = GenerateRandomString(NumericUpDown4.Value)
        End If
        If ListBox4.SelectedItem = "Replace" Then
            Dim XO = TextBox48.Text
            Dim xttTTT = TextBox45.Text
            TextBoxX12.Text = GenerateRandomString(NumericUpDown4.Value).Replace(XO, xttTTT)
        End If
        If ListBox4.SelectedItem = "Reverse" Then
            TextBoxX12.Text = Strings.StrReverse(GenerateRandomString(NumericUpDown4.Value))
        End If
        If ListBox4.SelectedItem = "Lowercase" Then
            TextBoxX12.Text = Strings.LCase(GenerateRandomString(NumericUpDown4.Value))
        End If
        If ListBox4.SelectedItem = "Uppercase" Then
            TextBoxX12.Text = Strings.UCase(GenerateRandomString(NumericUpDown4.Value))
        End If
    End Sub
#End Region
#Region "GEN 4"
    Private Sub TextBoxX14_MouseClick(sender As Object, e As MouseEventArgs) Handles TextBoxX14.MouseClick
        Dim rnd As New Random
        Dim randomIndex As String = rnd.Next(0, ListBox1.Items.Count)
        If ListBox5.SelectedItem = Nothing Then
            TextBoxX14.Text = ListBox1.Items(randomIndex)
        End If
        If ListBox5.SelectedItem = "Normal" Then
            TextBoxX14.Text = ListBox1.Items(randomIndex)
        End If
        If ListBox5.SelectedItem = "Replace" Then
            Dim XO = TextBox50.Text
            Dim xttTTT = TextBox49.Text
            TextBoxX14.Text = ListBox1.Items(randomIndex).Replace(XO, xttTTT)
        End If
        If ListBox5.SelectedItem = "Reverse" Then
            TextBoxX14.Text = Strings.StrReverse(ListBox1.Items(randomIndex))
        End If
        If ListBox5.SelectedItem = "Lowercase" Then
            TextBoxX14.Text = Strings.LCase(ListBox1.Items(randomIndex))
        End If
        If ListBox5.SelectedItem = "Uppercase" Then
            TextBoxX14.Text = Strings.UCase(ListBox1.Items(randomIndex))
        End If
    End Sub
    Private Sub TextBoxX14_MouseHover(sender As Object, e As EventArgs) Handles TextBoxX14.MouseHover
        If ListBox1.Items.Count = Nothing Then
            TextBoxX14.Enabled = False
        Else
            TextBoxX14.Enabled = True
        End If
    End Sub
#End Region
#Region "GEN 5"
    Private Sub TextBoxX15_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX15.MouseMove
        If ListBox6.SelectedItem = Nothing Then
            TextBoxX15.Text = Rnd()
        End If
        If ListBox6.SelectedItem = "Normal" Then
            TextBoxX15.Text = Rnd()
        End If
        If ListBox6.SelectedItem = "Replace" Then
            Dim XO = TextBox52.Text
            Dim xttTTT = TextBox51.Text
            TextBoxX15.Text = Rnd().ToString.Replace(XO, xttTTT)
        End If
        If ListBox6.SelectedItem = "Reverse" Then
            TextBoxX15.Text = Strings.StrReverse(Rnd())
        End If
        If ListBox6.SelectedItem = "Lowercase" Then
            TextBoxX15.Text = Strings.LCase(Rnd())
        End If
        If ListBox6.SelectedItem = "Uppercase" Then
            TextBoxX15.Text = Strings.UCase(Rnd())
        End If
    End Sub
#End Region
#Region "GEN 6"
    Private Sub TextBoxX16_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX16.MouseMove
        If ListBox7.SelectedItem = Nothing Then
            TextBoxX16.Text = RNV(NumericUpDown8.Value)
        End If
        If ListBox7.SelectedItem = "Normal" Then
            TextBoxX16.Text = RNV(NumericUpDown8.Value)
        End If
        If ListBox7.SelectedItem = "Replace" Then
            Dim XO = TextBox54.Text
            Dim xttTTT = TextBox53.Text
            TextBoxX16.Text = RNV(NumericUpDown8.Value).Replace(XO, xttTTT)
        End If
        If ListBox7.SelectedItem = "Reverse" Then
            TextBoxX16.Text = Strings.StrReverse(RNV(NumericUpDown8.Value))
        End If
        If ListBox7.SelectedItem = "Lowercase" Then
            TextBoxX16.Text = Strings.LCase(RNV(NumericUpDown8.Value))
        End If
        If ListBox7.SelectedItem = "Uppercase" Then
            TextBoxX16.Text = Strings.UCase(RNV(NumericUpDown8.Value))
        End If
    End Sub
#End Region
#Region "GEN 7"
    Private Sub TextBoxX17_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX17.MouseMove
        If ListBox8.SelectedItem = Nothing Then
            TextBoxX17.Text = MD5Hashrandom()
        End If
        If ListBox8.SelectedItem = "Normal" Then
            TextBoxX17.Text = MD5Hashrandom()
        End If
        If ListBox8.SelectedItem = "Replace" Then
            Dim XO = TextBox56.Text
            Dim xttTTT = TextBox55.Text
            TextBoxX17.Text = MD5Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox8.SelectedItem = "Reverse" Then
            TextBoxX17.Text = Strings.StrReverse(MD5Hashrandom())
        End If
        If ListBox8.SelectedItem = "Lowercase" Then
            TextBoxX17.Text = Strings.LCase(MD5Hashrandom())
        End If
        If ListBox8.SelectedItem = "Uppercase" Then
            TextBoxX17.Text = Strings.UCase(MD5Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 8"
    Private Sub TextBoxX18_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX18.MouseMove
        If ListBox9.SelectedItem = Nothing Then
            TextBoxX18.Text = SHA1Hashrandom()
        End If
        If ListBox9.SelectedItem = "Normal" Then
            TextBoxX18.Text = SHA1Hashrandom()
        End If
        If ListBox9.SelectedItem = "Replace" Then
            Dim XO = TextBox58.Text
            Dim xttTTT = TextBox57.Text
            TextBoxX18.Text = SHA1Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox9.SelectedItem = "Reverse" Then
            TextBoxX18.Text = Strings.StrReverse(SHA1Hashrandom())
        End If
        If ListBox9.SelectedItem = "Lowercase" Then
            TextBoxX18.Text = Strings.LCase(SHA1Hashrandom())
        End If
        If ListBox9.SelectedItem = "Uppercase" Then
            TextBoxX18.Text = Strings.UCase(SHA1Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 9"
    Private Sub TextBoxX19_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX19.MouseMove
        If ListBox10.SelectedItem = Nothing Then
            TextBoxX19.Text = SHA256Hashrandom()
        End If
        If ListBox10.SelectedItem = "Normal" Then
            TextBoxX19.Text = SHA256Hashrandom()
        End If
        If ListBox10.SelectedItem = "Replace" Then
            Dim XO = TextBox60.Text
            Dim xttTTT = TextBox59.Text
            TextBoxX19.Text = SHA256Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox10.SelectedItem = "Reverse" Then
            TextBoxX19.Text = Strings.StrReverse(SHA256Hashrandom())
        End If
        If ListBox10.SelectedItem = "Lowercase" Then
            TextBoxX19.Text = Strings.LCase(SHA256Hashrandom())
        End If
        If ListBox10.SelectedItem = "Uppercase" Then
            TextBoxX19.Text = Strings.UCase(SHA256Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 10"
    Private Sub TextBoxX20_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX20.MouseMove
        If ListBox11.SelectedItem = Nothing Then
            TextBoxX20.Text = SHA348Hashrandom()
        End If
        If ListBox11.SelectedItem = "Normal" Then
            TextBoxX20.Text = SHA348Hashrandom()
        End If
        If ListBox11.SelectedItem = "Replace" Then
            Dim XO = TextBox62.Text
            Dim xttTTT = TextBox61.Text
            TextBoxX20.Text = SHA348Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox11.SelectedItem = "Reverse" Then
            TextBoxX20.Text = Strings.StrReverse(SHA348Hashrandom())
        End If
        If ListBox11.SelectedItem = "Lowercase" Then
            TextBoxX20.Text = Strings.LCase(SHA348Hashrandom())
        End If
        If ListBox11.SelectedItem = "Uppercase" Then
            TextBoxX20.Text = Strings.UCase(SHA348Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 11"
    Private Sub TextBoxX21_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX21.MouseMove
        If ListBox12.SelectedItem = Nothing Then
            TextBoxX21.Text = SHA512Hashrandom()
        End If
        If ListBox12.SelectedItem = "Normal" Then
            TextBoxX21.Text = SHA512Hashrandom()
        End If
        If ListBox12.SelectedItem = "Replace" Then
            Dim XO = TextBox64.Text
            Dim xttTTT = TextBox63.Text
            TextBoxX21.Text = SHA512Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox12.SelectedItem = "Reverse" Then
            TextBoxX21.Text = Strings.StrReverse(SHA512Hashrandom())
        End If
        If ListBox12.SelectedItem = "Lowercase" Then
            TextBoxX21.Text = Strings.LCase(SHA512Hashrandom())
        End If
        If ListBox12.SelectedItem = "Uppercase" Then
            TextBoxX21.Text = Strings.UCase(SHA512Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 12"
    Private Sub TextBoxX22_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX22.MouseMove
        If ListBox13.SelectedItem = Nothing Then
            TextBoxX22.Text = RIPEMD160Hashrandom()
        End If
        If ListBox13.SelectedItem = "Normal" Then
            TextBoxX22.Text = RIPEMD160Hashrandom()
        End If
        If ListBox13.SelectedItem = "Replace" Then
            Dim XO = TextBox66.Text
            Dim xttTTT = TextBox65.Text
            TextBoxX22.Text = RIPEMD160Hashrandom().Replace(XO, xttTTT)
        End If
        If ListBox13.SelectedItem = "Reverse" Then
            TextBoxX22.Text = Strings.StrReverse(RIPEMD160Hashrandom())
        End If
        If ListBox13.SelectedItem = "Lowercase" Then
            TextBoxX22.Text = Strings.LCase(RIPEMD160Hashrandom())
        End If
        If ListBox13.SelectedItem = "Uppercase" Then
            TextBoxX22.Text = Strings.UCase(RIPEMD160Hashrandom())
        End If
    End Sub
#End Region
#Region "GEN 13"
    Private Sub TextBoxX23_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX23.MouseMove
        If ListBox14.SelectedItem = Nothing Then
            TextBoxX23.Text = Zip_Grandom()
        End If
        If ListBox14.SelectedItem = "Normal" Then
            TextBoxX23.Text = Zip_Grandom()
        End If
        If ListBox14.SelectedItem = "Replace" Then
            Dim XO = TextBox68.Text
            Dim xttTTT = TextBox67.Text
            TextBoxX23.Text = Zip_Grandom().Replace(XO, xttTTT)
        End If
        If ListBox14.SelectedItem = "Reverse" Then
            TextBoxX23.Text = Strings.StrReverse(Zip_Grandom())
        End If
        If ListBox14.SelectedItem = "Lowercase" Then
            TextBoxX23.Text = Strings.LCase(Zip_Grandom())
        End If
        If ListBox14.SelectedItem = "Uppercase" Then
            TextBoxX23.Text = Strings.UCase(Zip_Grandom())
        End If
    End Sub
#End Region
#Region "GEN 14"
    Private Sub TextBoxX24_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX24.MouseMove
        If ListBox15.SelectedItem = Nothing Then
            TextBoxX24.Text = Zip_deflaterandom()
        End If
        If ListBox15.SelectedItem = "Normal" Then
            TextBoxX24.Text = Zip_deflaterandom()
        End If
        If ListBox15.SelectedItem = "Replace" Then
            Dim XO = TextBox70.Text
            Dim xttTTT = TextBox69.Text
            TextBoxX24.Text = Zip_deflaterandom().Replace(XO, xttTTT)
        End If
        If ListBox15.SelectedItem = "Reverse" Then
            TextBoxX24.Text = Strings.StrReverse(Zip_deflaterandom())
        End If
        If ListBox15.SelectedItem = "Lowercase" Then
            TextBoxX24.Text = Strings.LCase(Zip_deflaterandom())
        End If
        If ListBox15.SelectedItem = "Uppercase" Then
            TextBoxX24.Text = Strings.UCase(Zip_deflaterandom())
        End If
    End Sub
#End Region
#Region "GEN 15"
    Private Sub TextBoxX25_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX25.MouseMove
        If ListBox16.SelectedItem = Nothing Then
            TextBoxX25.Text = CryptString_1random()
        End If
        If ListBox16.SelectedItem = "Normal" Then
            TextBoxX25.Text = CryptString_1random()
        End If
        If ListBox16.SelectedItem = "Replace" Then
            Dim XO = TextBox72.Text
            Dim xttTTT = TextBox71.Text
            TextBoxX25.Text = CryptString_1random().Replace(XO, xttTTT)
        End If
        If ListBox16.SelectedItem = "Reverse" Then
            TextBoxX25.Text = Strings.StrReverse(CryptString_1random())
        End If
        If ListBox16.SelectedItem = "Lowercase" Then
            TextBoxX25.Text = Strings.LCase(CryptString_1random())
        End If
        If ListBox16.SelectedItem = "Uppercase" Then
            TextBoxX25.Text = Strings.UCase(CryptString_1random())
        End If
    End Sub
#End Region
#Region "GEN 16"
    Private Sub TextBoxX26_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX26.MouseMove
        If ListBox17.SelectedItem = Nothing Then
            TextBoxX26.Text = converttolinerandom()
        End If
        If ListBox17.SelectedItem = "Normal" Then
            TextBoxX26.Text = converttolinerandom()
        End If
        If ListBox17.SelectedItem = "Replace" Then
            Dim XO = TextBox74.Text
            Dim xttTTT = TextBox73.Text
            TextBoxX26.Text = converttolinerandom().Replace(XO, xttTTT)
        End If
        If ListBox17.SelectedItem = "Reverse" Then
            TextBoxX26.Text = Strings.StrReverse(converttolinerandom())
        End If
        If ListBox17.SelectedItem = "Lowercase" Then
            TextBoxX26.Text = Strings.LCase(converttolinerandom())
        End If
        If ListBox17.SelectedItem = "Uppercase" Then
            TextBoxX26.Text = Strings.UCase(converttolinerandom())
        End If
    End Sub
#End Region
#Region "GEN 17"
    Private Sub TextBoxX27_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX27.MouseMove
        If ListBox18.SelectedItem = Nothing Then
            TextBoxX27.Text = Encrypt_CustomLinerandom()
        End If
        If ListBox18.SelectedItem = "Normal" Then
            TextBoxX27.Text = Encrypt_CustomLinerandom()
        End If
        If ListBox18.SelectedItem = "Replace" Then
            Dim XO = TextBox76.Text
            Dim xttTTT = TextBox75.Text
            TextBoxX27.Text = Encrypt_CustomLinerandom().Replace(XO, xttTTT)
        End If
        If ListBox18.SelectedItem = "Reverse" Then
            TextBoxX27.Text = Strings.StrReverse(Encrypt_CustomLinerandom())
        End If
        If ListBox18.SelectedItem = "Lowercase" Then
            TextBoxX27.Text = Strings.LCase(Encrypt_CustomLinerandom())
        End If
        If ListBox18.SelectedItem = "Uppercase" Then
            TextBoxX27.Text = Strings.UCase(Encrypt_CustomLinerandom())
        End If
    End Sub
#End Region
#Region "GEN 18"
    Private Sub TextBoxX28_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX28.MouseMove
        If ListBox19.SelectedItem = Nothing Then
            TextBoxX28.Text = binaryrandom()
        End If
        If ListBox19.SelectedItem = "Normal" Then
            TextBoxX28.Text = binaryrandom()
        End If
        If ListBox19.SelectedItem = "Replace" Then
            Dim XO = TextBox78.Text
            Dim xttTTT = TextBox77.Text
            TextBoxX28.Text = binaryrandom().Replace(XO, xttTTT)
        End If
        If ListBox19.SelectedItem = "Reverse" Then
            TextBoxX28.Text = Strings.StrReverse(binaryrandom())
        End If
        If ListBox19.SelectedItem = "Lowercase" Then
            TextBoxX28.Text = Strings.LCase(binaryrandom())
        End If
        If ListBox19.SelectedItem = "Uppercase" Then
            TextBoxX28.Text = Strings.UCase(binaryrandom())
        End If
    End Sub
#End Region
#Region "GEN 19"
    Private Sub TextBoxX29_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX29.MouseMove
        If ListBox20.SelectedItem = Nothing Then
            TextBoxX29.Text = HEXrandom()
        End If
        If ListBox20.SelectedItem = "Normal" Then
            TextBoxX29.Text = HEXrandom()
        End If
        If ListBox20.SelectedItem = "Replace" Then
            Dim XO = TextBox80.Text
            Dim xttTTT = TextBox79.Text
            TextBoxX29.Text = HEXrandom().Replace(XO, xttTTT)
        End If
        If ListBox20.SelectedItem = "Reverse" Then
            TextBoxX29.Text = Strings.StrReverse(HEXrandom())
        End If
        If ListBox20.SelectedItem = "Lowercase" Then
            TextBoxX29.Text = Strings.LCase(HEXrandom())
        End If
        If ListBox20.SelectedItem = "Uppercase" Then
            TextBoxX29.Text = Strings.UCase(HEXrandom())
        End If
    End Sub
#End Region
#Region "GEN 20"
    Private Sub TextBoxX30_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX30.MouseMove
        If ListBox21.SelectedItem = Nothing Then
            TextBoxX30.Text = pr0t3random()
        End If
        If ListBox21.SelectedItem = "Normal" Then
            TextBoxX30.Text = pr0t3random()
        End If
        If ListBox21.SelectedItem = "Replace" Then
            Dim XO = TextBox82.Text
            Dim xttTTT = TextBox81.Text
            TextBoxX30.Text = pr0t3random().Replace(XO, xttTTT)
        End If
        If ListBox21.SelectedItem = "Reverse" Then
            TextBoxX30.Text = Strings.StrReverse(pr0t3random())
        End If
        If ListBox21.SelectedItem = "Lowercase" Then
            TextBoxX30.Text = Strings.LCase(pr0t3random())
        End If
        If ListBox21.SelectedItem = "Uppercase" Then
            TextBoxX30.Text = Strings.UCase(pr0t3random())
        End If
    End Sub
#End Region
#Region "GEN 21"
    Private Sub TextBoxX31_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX31.MouseMove
        If ListBox22.SelectedItem = Nothing Then
            TextBoxX31.Text = RSArandom()
        End If
        If ListBox22.SelectedItem = "Normal" Then
            TextBoxX31.Text = RSArandom()
        End If
        If ListBox22.SelectedItem = "Replace" Then
            Dim XO = TextBox84.Text
            Dim xttTTT = TextBox83.Text
            TextBoxX31.Text = RSArandom().Replace(XO, xttTTT)
        End If
        If ListBox22.SelectedItem = "Reverse" Then
            TextBoxX31.Text = Strings.StrReverse(RSArandom())
        End If
        If ListBox22.SelectedItem = "Lowercase" Then
            TextBoxX31.Text = Strings.LCase(RSArandom())
        End If
        If ListBox22.SelectedItem = "Uppercase" Then
            TextBoxX31.Text = Strings.UCase(RSArandom())
        End If
    End Sub
#End Region
#Region "GEN 22"
    Private Sub TextBoxX32_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX32.MouseMove
        If ListBox23.SelectedItem = Nothing Then
            TextBoxX32.Text = Rot13random()
        End If
        If ListBox23.SelectedItem = "Normal" Then
            TextBoxX32.Text = Rot13random()
        End If
        If ListBox23.SelectedItem = "Replace" Then
            Dim XO = TextBox86.Text
            Dim xttTTT = TextBox85.Text
            TextBoxX32.Text = Rot13random().Replace(XO, xttTTT)
        End If
        If ListBox23.SelectedItem = "Reverse" Then
            TextBoxX32.Text = Strings.StrReverse(Rot13random())
        End If
        If ListBox23.SelectedItem = "Lowercase" Then
            TextBoxX32.Text = Strings.LCase(Rot13random())
        End If
        If ListBox23.SelectedItem = "Uppercase" Then
            TextBoxX32.Text = Strings.UCase(Rot13random())
        End If
    End Sub
#End Region
#Region "GEN 23"
    Private Sub TextBoxX33_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX33.MouseMove
        If ListBox24.SelectedItem = Nothing Then
            TextBoxX33.Text = BASE64random()
        End If
        If ListBox24.SelectedItem = "Normal" Then
            TextBoxX33.Text = BASE64random()
        End If
        If ListBox24.SelectedItem = "Replace" Then
            Dim XO = TextBox88.Text
            Dim xttTTT = TextBox87.Text
            TextBoxX33.Text = BASE64random().Replace(XO, xttTTT)
        End If
        If ListBox24.SelectedItem = "Reverse" Then
            TextBoxX33.Text = Strings.StrReverse(BASE64random())
        End If
        If ListBox24.SelectedItem = "Lowercase" Then
            TextBoxX33.Text = Strings.LCase(BASE64random())
        End If
        If ListBox24.SelectedItem = "Uppercase" Then
            TextBoxX33.Text = Strings.UCase(BASE64random())
        End If
    End Sub
#End Region
#Region "GEN 24"
    Private Sub TextBoxX34_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX34.MouseMove
        If ListBox25.SelectedItem = Nothing Then
            TextBoxX34.Text = MEGAN35random()
        End If
        If ListBox25.SelectedItem = "Normal" Then
            TextBoxX34.Text = MEGAN35random()
        End If
        If ListBox25.SelectedItem = "Replace" Then
            Dim XO = TextBox90.Text
            Dim xttTTT = TextBox89.Text
            TextBoxX34.Text = MEGAN35random().Replace(XO, xttTTT)
        End If
        If ListBox25.SelectedItem = "Reverse" Then
            TextBoxX34.Text = Strings.StrReverse(MEGAN35random())
        End If
        If ListBox25.SelectedItem = "Lowercase" Then
            TextBoxX34.Text = Strings.LCase(MEGAN35random())
        End If
        If ListBox25.SelectedItem = "Uppercase" Then
            TextBoxX34.Text = Strings.UCase(MEGAN35random())
        End If
    End Sub
#End Region
#Region "GEN 25"
    Private Sub TextBoxX35_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX35.MouseMove
        If ListBox26.SelectedItem = Nothing Then
            TextBoxX35.Text = ZONG22random()
        End If
        If ListBox26.SelectedItem = "Normal" Then
            TextBoxX35.Text = ZONG22random()
        End If
        If ListBox26.SelectedItem = "Replace" Then
            Dim XO = TextBox92.Text
            Dim xttTTT = TextBox91.Text
            TextBoxX35.Text = ZONG22random().Replace(XO, xttTTT)
        End If
        If ListBox26.SelectedItem = "Reverse" Then
            TextBoxX35.Text = Strings.StrReverse(ZONG22random())
        End If
        If ListBox26.SelectedItem = "Lowercase" Then
            TextBoxX35.Text = Strings.LCase(ZONG22random())
        End If
        If ListBox26.SelectedItem = "Uppercase" Then
            TextBoxX35.Text = Strings.UCase(ZONG22random())
        End If
    End Sub
#End Region
#Region "GEN 26"
    Private Sub TextBoxX36_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX36.MouseMove
        If ListBox27.SelectedItem = Nothing Then
            TextBoxX36.Text = TRIPO5random()
        End If
        If ListBox27.SelectedItem = "Normal" Then
            TextBoxX36.Text = TRIPO5random()
        End If
        If ListBox27.SelectedItem = "Replace" Then
            Dim XO = TextBox94.Text
            Dim xttTTT = TextBox93.Text
            TextBoxX36.Text = TRIPO5random().Replace(XO, xttTTT)
        End If
        If ListBox27.SelectedItem = "Reverse" Then
            TextBoxX36.Text = Strings.StrReverse(TRIPO5random())
        End If
        If ListBox27.SelectedItem = "Lowercase" Then
            TextBoxX36.Text = Strings.LCase(TRIPO5random())
        End If
        If ListBox27.SelectedItem = "Uppercase" Then
            TextBoxX36.Text = Strings.UCase(TRIPO5random())
        End If
    End Sub
#End Region
#Region "GEN 27"
    Private Sub TextBoxX37_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX37.MouseMove
        If ListBox28.SelectedItem = Nothing Then
            TextBoxX37.Text = TIGO3FXrandom()
        End If
        If ListBox28.SelectedItem = "Normal" Then
            TextBoxX37.Text = TIGO3FXrandom()
        End If
        If ListBox28.SelectedItem = "Replace" Then
            Dim XO = TextBox96.Text
            Dim xttTTT = TextBox95.Text
            TextBoxX37.Text = TIGO3FXrandom().Replace(XO, xttTTT)
        End If
        If ListBox28.SelectedItem = "Reverse" Then
            TextBoxX37.Text = Strings.StrReverse(TIGO3FXrandom())
        End If
        If ListBox28.SelectedItem = "Lowercase" Then
            TextBoxX37.Text = Strings.LCase(TIGO3FXrandom())
        End If
        If ListBox28.SelectedItem = "Uppercase" Then
            TextBoxX37.Text = Strings.UCase(TIGO3FXrandom())
        End If
    End Sub
#End Region
#Region "GEN 28"
    Private Sub TextBoxX38_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX38.MouseMove
        If ListBox29.SelectedItem = Nothing Then
            TextBoxX38.Text = FERON74random()
        End If
        If ListBox29.SelectedItem = "Normal" Then
            TextBoxX38.Text = FERON74random()
        End If
        If ListBox29.SelectedItem = "Replace" Then
            Dim XO = TextBox98.Text
            Dim xttTTT = TextBox97.Text
            TextBoxX38.Text = FERON74random().Replace(XO, xttTTT)
        End If
        If ListBox29.SelectedItem = "Reverse" Then
            TextBoxX38.Text = Strings.StrReverse(FERON74random())
        End If
        If ListBox29.SelectedItem = "Lowercase" Then
            TextBoxX38.Text = Strings.LCase(FERON74random())
        End If
        If ListBox29.SelectedItem = "Uppercase" Then
            TextBoxX38.Text = Strings.UCase(FERON74random())
        End If
    End Sub
#End Region
#Region "GEN 29"
    Private Sub TextBoxX39_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX39.MouseMove
        If ListBox30.SelectedItem = Nothing Then
            TextBoxX39.Text = ESAB46random()
        End If
        If ListBox30.SelectedItem = "Normal" Then
            TextBoxX39.Text = ESAB46random()
        End If
        If ListBox30.SelectedItem = "Replace" Then
            Dim XO = TextBox100.Text
            Dim xttTTT = TextBox99.Text
            TextBoxX39.Text = ESAB46random().Replace(XO, xttTTT)
        End If
        If ListBox30.SelectedItem = "Reverse" Then
            TextBoxX39.Text = Strings.StrReverse(ESAB46random())
        End If
        If ListBox30.SelectedItem = "Lowercase" Then
            TextBoxX39.Text = Strings.LCase(ESAB46random())
        End If
        If ListBox30.SelectedItem = "Uppercase" Then
            TextBoxX39.Text = Strings.UCase(ESAB46random())
        End If
    End Sub
#End Region
#Region "GEN 30"
    Private Sub TextBoxX40_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX40.MouseMove
        If ListBox31.SelectedItem = Nothing Then
            TextBoxX40.Text = GILA7random()
        End If
        If ListBox31.SelectedItem = "Normal" Then
            TextBoxX40.Text = GILA7random()
        End If
        If ListBox31.SelectedItem = "Replace" Then
            Dim XO = TextBox102.Text
            Dim xttTTT = TextBox101.Text
            TextBoxX40.Text = GILA7random().Replace(XO, xttTTT)
        End If
        If ListBox31.SelectedItem = "Reverse" Then
            TextBoxX40.Text = Strings.StrReverse(GILA7random())
        End If
        If ListBox31.SelectedItem = "Lowercase" Then
            TextBoxX40.Text = Strings.LCase(GILA7random())
        End If
        If ListBox31.SelectedItem = "Uppercase" Then
            TextBoxX40.Text = Strings.UCase(GILA7random())
        End If
    End Sub
#End Region
#Region "GEN 31"
    Private Sub TextBoxX41_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX41.MouseMove
        If ListBox32.SelectedItem = Nothing Then
            TextBoxX41.Text = HAZZ15random()
        End If
        If ListBox32.SelectedItem = "Normal" Then
            TextBoxX41.Text = HAZZ15random()
        End If
        If ListBox32.SelectedItem = "Replace" Then
            Dim XO = TextBox104.Text
            Dim xttTTT = TextBox103.Text
            TextBoxX41.Text = HAZZ15random().Replace(XO, xttTTT)
        End If
        If ListBox32.SelectedItem = "Reverse" Then
            TextBoxX41.Text = Strings.StrReverse(HAZZ15random())
        End If
        If ListBox32.SelectedItem = "Lowercase" Then
            TextBoxX41.Text = Strings.LCase(HAZZ15random())
        End If
        If ListBox32.SelectedItem = "Uppercase" Then
            TextBoxX41.Text = Strings.UCase(HAZZ15random())
        End If
    End Sub
#End Region
#Region "GEN 32"
    Private Sub TextBoxX42_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX42.MouseMove
        If ListBox33.SelectedItem = Nothing Then
            TextBoxX42.Text = Atom128random()
        End If
        If ListBox33.SelectedItem = "Normal" Then
            TextBoxX42.Text = Atom128random()
        End If
        If ListBox33.SelectedItem = "Replace" Then
            Dim XO = TextBox106.Text
            Dim xttTTT = TextBox105.Text
            TextBoxX42.Text = Atom128random().Replace(XO, xttTTT)
        End If
        If ListBox33.SelectedItem = "Reverse" Then
            TextBoxX42.Text = Strings.StrReverse(Atom128random())
        End If
        If ListBox33.SelectedItem = "Lowercase" Then
            TextBoxX42.Text = Strings.LCase(Atom128random())
        End If
        If ListBox33.SelectedItem = "Uppercase" Then
            TextBoxX42.Text = Strings.UCase(Atom128random())
        End If
    End Sub
#End Region
#Region "GEN 33"
    Private Sub TextBoxX43_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX43.MouseMove
        If ListBox34.SelectedItem = Nothing Then
            TextBoxX43.Text = Atbash_Cipherrandom()
        End If
        If ListBox34.SelectedItem = "Normal" Then
            TextBoxX43.Text = Atbash_Cipherrandom()
        End If
        If ListBox34.SelectedItem = "Replace" Then
            Dim XO = TextBox108.Text
            Dim xttTTT = TextBox107.Text
            TextBoxX43.Text = Atbash_Cipherrandom().Replace(XO, xttTTT)
        End If
        If ListBox34.SelectedItem = "Reverse" Then
            TextBoxX43.Text = Strings.StrReverse(Atbash_Cipherrandom())
        End If
        If ListBox34.SelectedItem = "Lowercase" Then
            TextBoxX43.Text = Strings.LCase(Atbash_Cipherrandom())
        End If
        If ListBox34.SelectedItem = "Uppercase" Then
            TextBoxX43.Text = Strings.UCase(Atbash_Cipherrandom())
        End If
    End Sub
#End Region
#Region "GEN 34"
    Private Sub TextBoxX44_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX44.MouseMove
        If ListBox35.SelectedItem = Nothing Then
            TextBoxX44.Text = ZARA128random()
        End If
        If ListBox35.SelectedItem = "Normal" Then
            TextBoxX44.Text = ZARA128random()
        End If
        If ListBox35.SelectedItem = "Replace" Then
            Dim XO = TextBox110.Text
            Dim xttTTT = TextBox109.Text
            TextBoxX44.Text = ZARA128random().Replace(XO, xttTTT)
        End If
        If ListBox35.SelectedItem = "Reverse" Then
            TextBoxX44.Text = Strings.StrReverse(ZARA128random())
        End If
        If ListBox35.SelectedItem = "Lowercase" Then
            TextBoxX44.Text = Strings.LCase(ZARA128random())
        End If
        If ListBox35.SelectedItem = "Uppercase" Then
            TextBoxX44.Text = Strings.UCase(ZARA128random())
        End If
    End Sub
#End Region
#Region "GEN 35"
    Private Sub TextBoxX45_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX45.MouseMove
        If ListBox36.SelectedItem = Nothing Then
            TextBoxX45.Text = ARMON64random()
        End If
        If ListBox36.SelectedItem = "Normal" Then
            TextBoxX45.Text = ARMON64random()
        End If
        If ListBox36.SelectedItem = "Replace" Then
            Dim XO = TextBox112.Text
            Dim xttTTT = TextBox111.Text
            TextBoxX45.Text = ARMON64random().Replace(XO, xttTTT)
        End If
        If ListBox36.SelectedItem = "Reverse" Then
            TextBoxX45.Text = Strings.StrReverse(ARMON64random())
        End If
        If ListBox36.SelectedItem = "Lowercase" Then
            TextBoxX45.Text = Strings.LCase(ARMON64random())
        End If
        If ListBox36.SelectedItem = "Uppercase" Then
            TextBoxX45.Text = Strings.UCase(ARMON64random())
        End If
    End Sub
#End Region
#Region "GEN 36"
    Private Sub TextBoxX46_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX46.MouseMove
        If ListBox37.SelectedItem = Nothing Then
            TextBoxX46.Text = Encryptrandom()
        End If
        If ListBox37.SelectedItem = "Normal" Then
            TextBoxX46.Text = Encryptrandom()
        End If
        If ListBox37.SelectedItem = "Replace" Then
            Dim XO = TextBox114.Text
            Dim xttTTT = TextBox113.Text
            TextBoxX46.Text = Encryptrandom().Replace(XO, xttTTT)
        End If
        If ListBox37.SelectedItem = "Reverse" Then
            TextBoxX46.Text = Strings.StrReverse(Encryptrandom())
        End If
        If ListBox37.SelectedItem = "Lowercase" Then
            TextBoxX46.Text = Strings.LCase(Encryptrandom())
        End If
        If ListBox37.SelectedItem = "Uppercase" Then
            TextBoxX46.Text = Strings.UCase(Encryptrandom())
        End If
    End Sub
#End Region
#Region "GEN 37"
    Private Sub TextBoxX47_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX47.MouseMove
        If ListBox38.SelectedItem = Nothing Then
            TextBoxX47.Text = AER256random()
        End If
        If ListBox38.SelectedItem = "Normal" Then
            TextBoxX47.Text = AER256random()
        End If
        If ListBox38.SelectedItem = "Replace" Then
            Dim XO = TextBox116.Text
            Dim xttTTT = TextBox115.Text
            TextBoxX47.Text = AER256random().Replace(XO, xttTTT)
        End If
        If ListBox38.SelectedItem = "Reverse" Then
            TextBoxX47.Text = Strings.StrReverse(AER256random())
        End If
        If ListBox38.SelectedItem = "Lowercase" Then
            TextBoxX47.Text = Strings.LCase(AER256random())
        End If
        If ListBox38.SelectedItem = "Uppercase" Then
            TextBoxX47.Text = Strings.UCase(AER256random())
        End If
    End Sub
#End Region
#Region "GEN 38"
    Private Sub TextBoxX52_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX52.MouseMove
        If ListBox39.SelectedItem = Nothing Then
            TextBoxX52.Text = EncryptDatarandom()
        End If
        If ListBox39.SelectedItem = "Normal" Then
            TextBoxX52.Text = EncryptDatarandom()
        End If
        If ListBox39.SelectedItem = "Replace" Then
            Dim XO = TextBox118.Text
            Dim xttTTT = TextBox117.Text
            TextBoxX52.Text = EncryptDatarandom().Replace(XO, xttTTT)
        End If
        If ListBox39.SelectedItem = "Reverse" Then
            TextBoxX52.Text = Strings.StrReverse(EncryptDatarandom())
        End If
        If ListBox39.SelectedItem = "Lowercase" Then
            TextBoxX52.Text = Strings.LCase(EncryptDatarandom())
        End If
        If ListBox39.SelectedItem = "Uppercase" Then
            TextBoxX52.Text = Strings.UCase(EncryptDatarandom())
        End If
    End Sub
#End Region
#Region "GEN 39"
    Private Sub TextBoxX53_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX53.MouseMove
        If ListBox40.SelectedItem = Nothing Then
            TextBoxX53.Text = HMACMD5()
        End If
        If ListBox40.SelectedItem = "Normal" Then
            TextBoxX53.Text = HMACMD5()
        End If
        If ListBox40.SelectedItem = "Replace" Then
            Dim XO = TextBox120.Text
            Dim xttTTT = TextBox119.Text
            TextBoxX53.Text = HMACMD5().Replace(XO, xttTTT)
        End If
        If ListBox40.SelectedItem = "Reverse" Then
            TextBoxX53.Text = Strings.StrReverse(HMACMD5())
        End If
        If ListBox40.SelectedItem = "Lowercase" Then
            TextBoxX53.Text = Strings.LCase(HMACMD5())
        End If
        If ListBox40.SelectedItem = "Uppercase" Then
            TextBoxX53.Text = Strings.UCase(HMACMD5())
        End If
    End Sub
#End Region
#Region "GEN 40"
    Private Sub TextBoxX54_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX54.MouseMove
        If ListBox41.SelectedItem = Nothing Then
            TextBoxX54.Text = HMACRIPEMD160()
        End If
        If ListBox41.SelectedItem = "Normal" Then
            TextBoxX54.Text = HMACRIPEMD160()
        End If
        If ListBox41.SelectedItem = "Replace" Then
            Dim XO = TextBox122.Text
            Dim xttTTT = TextBox121.Text
            TextBoxX54.Text = HMACRIPEMD160().Replace(XO, xttTTT)
        End If
        If ListBox41.SelectedItem = "Reverse" Then
            TextBoxX54.Text = Strings.StrReverse(HMACRIPEMD160())
        End If
        If ListBox41.SelectedItem = "Lowercase" Then
            TextBoxX54.Text = Strings.LCase(HMACRIPEMD160())
        End If
        If ListBox41.SelectedItem = "Uppercase" Then
            TextBoxX54.Text = Strings.UCase(HMACRIPEMD160())
        End If
    End Sub
#End Region
#Region "GEN 41"
    Private Sub TextBoxX55_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX55.MouseMove
        If ListBox42.SelectedItem = Nothing Then
            TextBoxX55.Text = HMACSHA1()
        End If
        If ListBox42.SelectedItem = "Normal" Then
            TextBoxX55.Text = HMACSHA1()
        End If
        If ListBox42.SelectedItem = "Replace" Then
            Dim XO = TextBox124.Text
            Dim xttTTT = TextBox123.Text
            TextBoxX55.Text = HMACSHA1().Replace(XO, xttTTT)
        End If
        If ListBox42.SelectedItem = "Reverse" Then
            TextBoxX55.Text = Strings.StrReverse(HMACSHA1())
        End If
        If ListBox42.SelectedItem = "Lowercase" Then
            TextBoxX55.Text = Strings.LCase(HMACSHA1())
        End If
        If ListBox42.SelectedItem = "Uppercase" Then
            TextBoxX55.Text = Strings.UCase(HMACSHA1())
        End If
    End Sub
#End Region
#Region "GEN 42"
    Private Sub TextBoxX56_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX56.MouseMove
        If ListBox43.SelectedItem = Nothing Then
            TextBoxX56.Text = HMACSHA256()
        End If
        If ListBox43.SelectedItem = "Normal" Then
            TextBoxX56.Text = HMACSHA256()
        End If
        If ListBox43.SelectedItem = "Replace" Then
            Dim XO = TextBox126.Text
            Dim xttTTT = TextBox125.Text
            TextBoxX56.Text = HMACSHA256().Replace(XO, xttTTT)
        End If
        If ListBox43.SelectedItem = "Reverse" Then
            TextBoxX56.Text = Strings.StrReverse(HMACSHA256())
        End If
        If ListBox43.SelectedItem = "Lowercase" Then
            TextBoxX56.Text = Strings.LCase(HMACSHA256())
        End If
        If ListBox43.SelectedItem = "Uppercase" Then
            TextBoxX56.Text = Strings.UCase(HMACSHA256())
        End If
    End Sub
#End Region
#Region "GEN 43"
    Private Sub TextBoxX57_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX57.MouseMove
        If ListBox44.SelectedItem = Nothing Then
            TextBoxX57.Text = HMACSHA384()
        End If
        If ListBox44.SelectedItem = "Normal" Then
            TextBoxX57.Text = HMACSHA384()
        End If
        If ListBox44.SelectedItem = "Replace" Then
            Dim XO = TextBox128.Text
            Dim xttTTT = TextBox127.Text
            TextBoxX57.Text = HMACSHA384().Replace(XO, xttTTT)
        End If
        If ListBox44.SelectedItem = "Reverse" Then
            TextBoxX57.Text = Strings.StrReverse(HMACSHA384())
        End If
        If ListBox44.SelectedItem = "Lowercase" Then
            TextBoxX57.Text = Strings.LCase(HMACSHA384())
        End If
        If ListBox44.SelectedItem = "Uppercase" Then
            TextBoxX57.Text = Strings.UCase(HMACSHA384())
        End If
    End Sub
#End Region
#Region "GEN 44"
    Private Sub TextBoxX58_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX58.MouseMove
        If ListBox45.SelectedItem = Nothing Then
            TextBoxX58.Text = HMACSHA512()
        End If
        If ListBox45.SelectedItem = "Normal" Then
            TextBoxX58.Text = HMACSHA512()
        End If
        If ListBox45.SelectedItem = "Replace" Then
            Dim XO = TextBox130.Text
            Dim xttTTT = TextBox129.Text
            TextBoxX58.Text = HMACSHA512().Replace(XO, xttTTT)
        End If
        If ListBox45.SelectedItem = "Reverse" Then
            TextBoxX58.Text = Strings.StrReverse(HMACSHA512())
        End If
        If ListBox45.SelectedItem = "Lowercase" Then
            TextBoxX58.Text = Strings.LCase(HMACSHA512())
        End If
        If ListBox45.SelectedItem = "Uppercase" Then
            TextBoxX58.Text = Strings.UCase(HMACSHA512())
        End If
    End Sub
#End Region
#Region "GEN 45"
    Private Sub TextBoxX59_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX59.MouseMove
        If ListBox46.SelectedItem = Nothing Then
            TextBoxX59.Text = MACTripleDES()
        End If
        If ListBox46.SelectedItem = "Normal" Then
            TextBoxX59.Text = MACTripleDES()
        End If
        If ListBox46.SelectedItem = "Replace" Then
            Dim XO = TextBox132.Text
            Dim xttTTT = TextBox131.Text
            TextBoxX59.Text = MACTripleDES().Replace(XO, xttTTT)
        End If
        If ListBox46.SelectedItem = "Reverse" Then
            TextBoxX59.Text = Strings.StrReverse(MACTripleDES())
        End If
        If ListBox46.SelectedItem = "Lowercase" Then
            TextBoxX59.Text = Strings.LCase(MACTripleDES())
        End If
        If ListBox46.SelectedItem = "Uppercase" Then
            TextBoxX59.Text = Strings.UCase(MACTripleDES())
        End If
    End Sub
#End Region
#Region "GEN 46"
    Private Sub TextBoxX60_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX60.MouseMove
        If ListBox47.SelectedItem = Nothing Then
            TextBoxX60.Text = MD5_64()
        End If
        If ListBox47.SelectedItem = "Normal" Then
            TextBoxX60.Text = MD5_64()
        End If
        If ListBox47.SelectedItem = "Replace" Then
            Dim XO = TextBox134.Text
            Dim xttTTT = TextBox133.Text
            TextBoxX60.Text = MD5_64().Replace(XO, xttTTT)
        End If
        If ListBox47.SelectedItem = "Reverse" Then
            TextBoxX60.Text = Strings.StrReverse(MD5_64())
        End If
        If ListBox47.SelectedItem = "Lowercase" Then
            TextBoxX60.Text = Strings.LCase(MD5_64())
        End If
        If ListBox47.SelectedItem = "Uppercase" Then
            TextBoxX60.Text = Strings.UCase(MD5_64())
        End If
    End Sub
#End Region
#Region "GEN 47"
    Private Sub TextBoxX61_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX61.MouseMove
        If ListBox48.SelectedItem = Nothing Then
            TextBoxX61.Text = EncryptSHA512Managed()
        End If
        If ListBox48.SelectedItem = "Normal" Then
            TextBoxX61.Text = EncryptSHA512Managed()
        End If
        If ListBox48.SelectedItem = "Replace" Then
            Dim XO = TextBox136.Text
            Dim xttTTT = TextBox135.Text
            TextBoxX61.Text = EncryptSHA512Managed().Replace(XO, xttTTT)
        End If
        If ListBox48.SelectedItem = "Reverse" Then
            TextBoxX61.Text = Strings.StrReverse(EncryptSHA512Managed())
        End If
        If ListBox48.SelectedItem = "Lowercase" Then
            TextBoxX61.Text = Strings.LCase(EncryptSHA512Managed())
        End If
        If ListBox48.SelectedItem = "Uppercase" Then
            TextBoxX61.Text = Strings.UCase(EncryptSHA512Managed())
        End If
    End Sub
#End Region
#Region "GEN 48"
    Private Sub TextBoxX62_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX62.MouseMove
        If ListBox49.SelectedItem = Nothing Then
            TextBoxX62.Text = rc4()
        End If
        If ListBox49.SelectedItem = "Normal" Then
            TextBoxX62.Text = rc4()
        End If
        If ListBox49.SelectedItem = "Replace" Then
            Dim XO = TextBox138.Text
            Dim xttTTT = TextBox137.Text
            TextBoxX62.Text = rc4().Replace(XO, xttTTT)
        End If
        If ListBox49.SelectedItem = "Reverse" Then
            TextBoxX62.Text = Strings.StrReverse(rc4())
        End If
        If ListBox49.SelectedItem = "Lowercase" Then
            TextBoxX62.Text = Strings.LCase(rc4())
        End If
        If ListBox49.SelectedItem = "Uppercase" Then
            TextBoxX62.Text = Strings.UCase(rc4())
        End If
    End Sub
#End Region
#Region "GEN 49"
    Private Sub TextBoxX63_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX63.MouseMove
        If ListBox50.SelectedItem = Nothing Then
            TextBoxX63.Text = THIRD_DES()
        End If
        If ListBox50.SelectedItem = "Normal" Then
            TextBoxX63.Text = THIRD_DES()
        End If
        If ListBox50.SelectedItem = "Replace" Then
            Dim XO = TextBox140.Text
            Dim xttTTT = TextBox139.Text
            TextBoxX63.Text = THIRD_DES().Replace(XO, xttTTT)
        End If
        If ListBox50.SelectedItem = "Reverse" Then
            TextBoxX63.Text = Strings.StrReverse(THIRD_DES())
        End If
        If ListBox50.SelectedItem = "Lowercase" Then
            TextBoxX63.Text = Strings.LCase(THIRD_DES())
        End If
        If ListBox50.SelectedItem = "Uppercase" Then
            TextBoxX63.Text = Strings.UCase(THIRD_DES())
        End If
    End Sub
#End Region
#Region "GEN 50"
    Private Sub TextBoxX64_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX64.MouseMove
        If ListBox51.SelectedItem = Nothing Then
            TextBoxX64.Text = AES()
        End If
        If ListBox51.SelectedItem = "Normal" Then
            TextBoxX64.Text = AES()
        End If
        If ListBox51.SelectedItem = "Replace" Then
            Dim XO = TextBox142.Text
            Dim xttTTT = TextBox141.Text
            TextBoxX64.Text = AES().Replace(XO, xttTTT)
        End If
        If ListBox51.SelectedItem = "Reverse" Then
            TextBoxX64.Text = Strings.StrReverse(AES())
        End If
        If ListBox51.SelectedItem = "Lowercase" Then
            TextBoxX64.Text = Strings.LCase(AES())
        End If
        If ListBox51.SelectedItem = "Uppercase" Then
            TextBoxX64.Text = Strings.UCase(AES())
        End If
    End Sub
#End Region
#Region "GEN 51"
    Private Sub TextBoxX65_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX65.MouseMove
        If ListBox52.SelectedItem = Nothing Then
            TextBoxX65.Text = CeaserChipher()
        End If
        If ListBox52.SelectedItem = "Normal" Then
            TextBoxX65.Text = CeaserChipher()
        End If
        If ListBox52.SelectedItem = "Replace" Then
            Dim XO = TextBox144.Text
            Dim xttTTT = TextBox143.Text
            TextBoxX65.Text = CeaserChipher().Replace(XO, xttTTT)
        End If
        If ListBox52.SelectedItem = "Reverse" Then
            TextBoxX65.Text = Strings.StrReverse(CeaserChipher())
        End If
        If ListBox52.SelectedItem = "Lowercase" Then
            TextBoxX65.Text = Strings.LCase(CeaserChipher())
        End If
        If ListBox52.SelectedItem = "Uppercase" Then
            TextBoxX65.Text = Strings.UCase(CeaserChipher())
        End If
    End Sub
#End Region
#Region "GEN 52"
    Private Sub TextBoxX66_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX66.MouseMove
        If ListBox53.SelectedItem = Nothing Then
            TextBoxX66.Text = CustomXOR()
        End If
        If ListBox53.SelectedItem = "Normal" Then
            TextBoxX66.Text = CustomXOR()
        End If
        If ListBox53.SelectedItem = "Replace" Then
            Dim XO = TextBox146.Text
            Dim xttTTT = TextBox145.Text
            TextBoxX66.Text = CustomXOR().Replace(XO, xttTTT)
        End If
        If ListBox53.SelectedItem = "Reverse" Then
            TextBoxX66.Text = Strings.StrReverse(CustomXOR())
        End If
        If ListBox53.SelectedItem = "Lowercase" Then
            TextBoxX66.Text = Strings.LCase(CustomXOR())
        End If
        If ListBox53.SelectedItem = "Uppercase" Then
            TextBoxX66.Text = Strings.UCase(CustomXOR())
        End If
    End Sub
#End Region
#Region "GEN 53"
    Private Sub TextBoxX67_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX67.MouseMove
        If ListBox54.SelectedItem = Nothing Then
            TextBoxX67.Text = DES()
        End If
        If ListBox54.SelectedItem = "Normal" Then
            TextBoxX67.Text = DES()
        End If
        If ListBox54.SelectedItem = "Replace" Then
            Dim XO = TextBox148.Text
            Dim xttTTT = TextBox147.Text
            TextBoxX67.Text = DES().Replace(XO, xttTTT)
        End If
        If ListBox54.SelectedItem = "Reverse" Then
            TextBoxX67.Text = Strings.StrReverse(DES())
        End If
        If ListBox54.SelectedItem = "Lowercase" Then
            TextBoxX67.Text = Strings.LCase(DES())
        End If
        If ListBox54.SelectedItem = "Uppercase" Then
            TextBoxX67.Text = Strings.UCase(DES())
        End If
    End Sub
#End Region
#Region "GEN 54"
    Private Sub TextBoxX68_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX68.MouseMove
        If ListBox55.SelectedItem = Nothing Then
            TextBoxX68.Text = Envy()
        End If
        If ListBox55.SelectedItem = "Normal" Then
            TextBoxX68.Text = Envy()
        End If
        If ListBox55.SelectedItem = "Replace" Then
            Dim XO = TextBox150.Text
            Dim xttTTT = TextBox149.Text
            TextBoxX68.Text = Envy().Replace(XO, xttTTT)
        End If
        If ListBox55.SelectedItem = "Reverse" Then
            TextBoxX68.Text = Strings.StrReverse(Envy())
        End If
        If ListBox55.SelectedItem = "Lowercase" Then
            TextBoxX68.Text = Strings.LCase(Envy())
        End If
        If ListBox55.SelectedItem = "Uppercase" Then
            TextBoxX68.Text = Strings.UCase(Envy())
        End If
    End Sub
#End Region
#Region "GEN 55"
    Private Sub TextBoxX69_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX69.MouseMove
        If ListBox56.SelectedItem = Nothing Then
            TextBoxX69.Text = PolymorphicRC4()
        End If
        If ListBox56.SelectedItem = "Normal" Then
            TextBoxX69.Text = PolymorphicRC4()
        End If
        If ListBox56.SelectedItem = "Replace" Then
            Dim XO = TextBox152.Text
            Dim xttTTT = TextBox151.Text
            TextBoxX69.Text = PolymorphicRC4().Replace(XO, xttTTT)
        End If
        If ListBox56.SelectedItem = "Reverse" Then
            TextBoxX69.Text = Strings.StrReverse(PolymorphicRC4())
        End If
        If ListBox56.SelectedItem = "Lowercase" Then
            TextBoxX69.Text = Strings.LCase(PolymorphicRC4())
        End If
        If ListBox56.SelectedItem = "Uppercase" Then
            TextBoxX69.Text = Strings.UCase(PolymorphicRC4())
        End If
    End Sub
#End Region
#Region "GEN 56"
    Private Sub TextBoxX70_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX70.MouseMove
        If ListBox57.SelectedItem = Nothing Then
            TextBoxX70.Text = PolymorphicStairs()
        End If
        If ListBox57.SelectedItem = "Normal" Then
            TextBoxX70.Text = PolymorphicStairs()
        End If
        If ListBox57.SelectedItem = "Replace" Then
            Dim XO = TextBox154.Text
            Dim xttTTT = TextBox153.Text
            TextBoxX70.Text = PolymorphicStairs().Replace(XO, xttTTT)
        End If
        If ListBox57.SelectedItem = "Reverse" Then
            TextBoxX70.Text = Strings.StrReverse(PolymorphicStairs())
        End If
        If ListBox57.SelectedItem = "Lowercase" Then
            TextBoxX70.Text = Strings.LCase(PolymorphicStairs())
        End If
        If ListBox57.SelectedItem = "Uppercase" Then
            TextBoxX70.Text = Strings.UCase(PolymorphicStairs())
        End If
    End Sub
#End Region
#Region "GEN 57"
    Private Sub TextBoxX71_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX71.MouseMove
        If ListBox58.SelectedItem = Nothing Then
            TextBoxX71.Text = rc2()
        End If
        If ListBox58.SelectedItem = "Normal" Then
            TextBoxX71.Text = rc2()
        End If
        If ListBox58.SelectedItem = "Replace" Then
            Dim XO = TextBox156.Text
            Dim xttTTT = TextBox155.Text
            TextBoxX71.Text = rc2().Replace(XO, xttTTT)
        End If
        If ListBox58.SelectedItem = "Reverse" Then
            TextBoxX71.Text = Strings.StrReverse(rc2())
        End If
        If ListBox58.SelectedItem = "Lowercase" Then
            TextBoxX71.Text = Strings.LCase(rc2())
        End If
        If ListBox58.SelectedItem = "Uppercase" Then
            TextBoxX71.Text = Strings.UCase(rc2())
        End If
    End Sub
#End Region
#Region "GEN 58"
    Private Sub TextBoxX72_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX72.MouseMove
        If ListBox59.SelectedItem = Nothing Then
            TextBoxX72.Text = rc4random()
        End If
        If ListBox59.SelectedItem = "Normal" Then
            TextBoxX72.Text = rc4random()
        End If
        If ListBox59.SelectedItem = "Replace" Then
            Dim XO = TextBox158.Text
            Dim xttTTT = TextBox157.Text
            TextBoxX72.Text = rc4random().Replace(XO, xttTTT)
        End If
        If ListBox59.SelectedItem = "Reverse" Then
            TextBoxX72.Text = Strings.StrReverse(rc4random())
        End If
        If ListBox59.SelectedItem = "Lowercase" Then
            TextBoxX72.Text = Strings.LCase(rc4random())
        End If
        If ListBox59.SelectedItem = "Uppercase" Then
            TextBoxX72.Text = Strings.UCase(rc4random())
        End If
    End Sub
#End Region
#Region "GEN 59"
    Private Sub TextBoxX73_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX73.MouseMove
        If ListBox60.SelectedItem = Nothing Then
            TextBoxX73.Text = Rijndael()
        End If
        If ListBox60.SelectedItem = "Normal" Then
            TextBoxX73.Text = Rijndael()
        End If
        If ListBox60.SelectedItem = "Replace" Then
            Dim XO = TextBox160.Text
            Dim xttTTT = TextBox159.Text
            TextBoxX73.Text = Rijndael().Replace(XO, xttTTT)
        End If
        If ListBox60.SelectedItem = "Reverse" Then
            TextBoxX73.Text = Strings.StrReverse(Rijndael())
        End If
        If ListBox60.SelectedItem = "Lowercase" Then
            TextBoxX73.Text = Strings.LCase(Rijndael())
        End If
        If ListBox60.SelectedItem = "Uppercase" Then
            TextBoxX73.Text = Strings.UCase(Rijndael())
        End If
    End Sub
#End Region
#Region "GEN 60"
    Private Sub TextBoxX74_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX74.MouseMove
        If ListBox61.SelectedItem = Nothing Then
            TextBoxX74.Text = Stairs()
        End If
        If ListBox61.SelectedItem = "Normal" Then
            TextBoxX74.Text = Stairs()
        End If
        If ListBox61.SelectedItem = "Replace" Then
            Dim XO = TextBox162.Text
            Dim xttTTT = TextBox161.Text
            TextBoxX74.Text = Stairs().Replace(XO, xttTTT)
        End If
        If ListBox61.SelectedItem = "Reverse" Then
            TextBoxX74.Text = Strings.StrReverse(Stairs())
        End If
        If ListBox61.SelectedItem = "Lowercase" Then
            TextBoxX74.Text = Strings.LCase(Stairs())
        End If
        If ListBox61.SelectedItem = "Uppercase" Then
            TextBoxX74.Text = Strings.UCase(Stairs())
        End If
    End Sub
#End Region
#Region "GEN 61"
    Private Sub TextBoxX75_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX75.MouseMove
        If ListBox62.SelectedItem = Nothing Then
            TextBoxX75.Text = TripleDESrand()
        End If
        If ListBox62.SelectedItem = "Normal" Then
            TextBoxX75.Text = TripleDESrand()
        End If
        If ListBox62.SelectedItem = "Replace" Then
            Dim XO = TextBox164.Text
            Dim xttTTT = TextBox163.Text
            TextBoxX75.Text = TripleDESrand().Replace(XO, xttTTT)
        End If
        If ListBox62.SelectedItem = "Reverse" Then
            TextBoxX75.Text = Strings.StrReverse(TripleDESrand())
        End If
        If ListBox62.SelectedItem = "Lowercase" Then
            TextBoxX75.Text = Strings.LCase(TripleDESrand())
        End If
        If ListBox62.SelectedItem = "Uppercase" Then
            TextBoxX75.Text = Strings.UCase(TripleDESrand())
        End If
    End Sub
#End Region
#Region "GEN 62"
    Private Sub TextBoxX76_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX76.MouseMove
        If ListBox63.SelectedItem = Nothing Then
            TextBoxX76.Text = Vernam()
        End If
        If ListBox63.SelectedItem = "Normal" Then
            TextBoxX76.Text = Vernam()
        End If
        If ListBox63.SelectedItem = "Replace" Then
            Dim XO = TextBox166.Text
            Dim xttTTT = TextBox165.Text
            TextBoxX76.Text = Vernam().Replace(XO, xttTTT)
        End If
        If ListBox63.SelectedItem = "Reverse" Then
            TextBoxX76.Text = Strings.StrReverse(Vernam())
        End If
        If ListBox63.SelectedItem = "Lowercase" Then
            TextBoxX76.Text = Strings.LCase(Vernam())
        End If
        If ListBox63.SelectedItem = "Uppercase" Then
            TextBoxX76.Text = Strings.UCase(Vernam())
        End If
    End Sub
#End Region
#Region "GEN 63"
    Private Sub TextBoxX77_MouseMove(sender As Object, e As MouseEventArgs) Handles TextBoxX77.MouseMove
        If ListBox64.SelectedItem = Nothing Then
            TextBoxX77.Text = XORrandom()
        End If
        If ListBox64.SelectedItem = "Normal" Then
            TextBoxX77.Text = XORrandom()
        End If
        If ListBox64.SelectedItem = "Replace" Then
            Dim XO = TextBox168.Text
            Dim xttTTT = TextBox167.Text
            TextBoxX77.Text = XORrandom().Replace(XO, xttTTT)
        End If
        If ListBox64.SelectedItem = "Reverse" Then
            TextBoxX77.Text = Strings.StrReverse(XORrandom())
        End If
        If ListBox64.SelectedItem = "Lowercase" Then
            TextBoxX77.Text = Strings.LCase(XORrandom())
        End If
        If ListBox64.SelectedItem = "Uppercase" Then
            TextBoxX77.Text = Strings.UCase(XORrandom())
        End If
    End Sub
#End Region
#End Region
#Region "Clipboard"
    Private Sub ButtonX56_Click(sender As Object, e As EventArgs) Handles ButtonX56.Click
        Clipboard.SetText(TextBoxX48.Text)
    End Sub
    Private Sub ButtonX55_Click(sender As Object, e As EventArgs) Handles ButtonX55.Click
        Clipboard.SetText(TextBoxX47.Text)
    End Sub
    Private Sub ButtonX54_Click(sender As Object, e As EventArgs) Handles ButtonX54.Click
        Clipboard.SetText(TextBoxX46.Text)
    End Sub
    Private Sub ButtonX53_Click(sender As Object, e As EventArgs) Handles ButtonX53.Click
        Clipboard.SetText(TextBoxX45.Text)
    End Sub
    Private Sub ButtonX52_Click(sender As Object, e As EventArgs) Handles ButtonX52.Click
        Clipboard.SetText(TextBoxX44.Text)
    End Sub
    Private Sub ButtonX51_Click(sender As Object, e As EventArgs) Handles ButtonX51.Click
        Clipboard.SetText(TextBoxX43.Text)
    End Sub
    Private Sub ButtonX50_Click(sender As Object, e As EventArgs) Handles ButtonX50.Click
        Clipboard.SetText(TextBoxX42.Text)
    End Sub
    Private Sub ButtonX48_Click(sender As Object, e As EventArgs) Handles ButtonX48.Click
        Clipboard.SetText(TextBoxX40.Text)
    End Sub
    Private Sub ButtonX49_Click(sender As Object, e As EventArgs) Handles ButtonX49.Click
        Clipboard.SetText(TextBoxX41.Text)
    End Sub
    Private Sub ButtonX18_Click(sender As Object, e As EventArgs) Handles ButtonX18.Click
        Clipboard.SetText(TextBoxX2.Text)
    End Sub
    Private Sub ButtonX19_Click(sender As Object, e As EventArgs) Handles ButtonX19.Click
        Clipboard.SetText(TextBoxX3.Text)
    End Sub
    Private Sub ButtonX21_Click(sender As Object, e As EventArgs) Handles ButtonX21.Click
        Clipboard.SetText(TextBoxX12.Text)
    End Sub
    Private Sub ButtonX22_Click(sender As Object, e As EventArgs) Handles ButtonX22.Click
        Clipboard.SetText(TextBoxX14.Text)
    End Sub
    Private Sub ButtonX23_Click(sender As Object, e As EventArgs) Handles ButtonX23.Click
        Clipboard.SetText(TextBoxX15.Text)
    End Sub
    Private Sub ButtonX24_Click(sender As Object, e As EventArgs) Handles ButtonX24.Click
        Clipboard.SetText(TextBoxX16.Text)
    End Sub
    Private Sub ButtonX25_Click(sender As Object, e As EventArgs) Handles ButtonX25.Click
        Clipboard.SetText(TextBoxX17.Text)
    End Sub
    Private Sub ButtonX47_Click(sender As Object, e As EventArgs) Handles ButtonX47.Click
        Clipboard.SetText(TextBoxX39.Text)
    End Sub
    Private Sub ButtonX40_Click(sender As Object, e As EventArgs) Handles ButtonX40.Click
        Clipboard.SetText(TextBoxX32.Text)
    End Sub
    Private Sub ButtonX41_Click(sender As Object, e As EventArgs) Handles ButtonX41.Click
        Clipboard.SetText(TextBoxX33.Text)
    End Sub
    Private Sub ButtonX42_Click(sender As Object, e As EventArgs) Handles ButtonX42.Click
        Clipboard.SetText(TextBoxX34.Text)
    End Sub
    Private Sub ButtonX43_Click(sender As Object, e As EventArgs) Handles ButtonX43.Click
        Clipboard.SetText(TextBoxX35.Text)
    End Sub
    Private Sub ButtonX44_Click(sender As Object, e As EventArgs) Handles ButtonX44.Click
        Clipboard.SetText(TextBoxX36.Text)
    End Sub
    Private Sub ButtonX45_Click(sender As Object, e As EventArgs) Handles ButtonX45.Click
        Clipboard.SetText(TextBoxX37.Text)
    End Sub
    Private Sub ButtonX46_Click(sender As Object, e As EventArgs) Handles ButtonX46.Click
        Clipboard.SetText(TextBoxX38.Text)
    End Sub
    Private Sub ButtonX39_Click(sender As Object, e As EventArgs) Handles ButtonX39.Click
        Clipboard.SetText(TextBoxX31.Text)
    End Sub
    Private Sub ButtonX38_Click(sender As Object, e As EventArgs) Handles ButtonX38.Click
        Clipboard.SetText(TextBoxX30.Text)
    End Sub
    Private Sub ButtonX37_Click(sender As Object, e As EventArgs) Handles ButtonX37.Click
        Clipboard.SetText(TextBoxX29.Text)
    End Sub
    Private Sub ButtonX36_Click(sender As Object, e As EventArgs) Handles ButtonX36.Click
        Clipboard.SetText(TextBoxX28.Text)
    End Sub
    Private Sub ButtonX35_Click(sender As Object, e As EventArgs) Handles ButtonX35.Click
        Clipboard.SetText(TextBoxX27.Text)
    End Sub
    Private Sub ButtonX34_Click(sender As Object, e As EventArgs) Handles ButtonX34.Click
        Clipboard.SetText(TextBoxX26.Text)
    End Sub
    Private Sub ButtonX33_Click(sender As Object, e As EventArgs) Handles ButtonX33.Click
        Clipboard.SetText(TextBoxX25.Text)
    End Sub
    Private Sub ButtonX32_Click(sender As Object, e As EventArgs) Handles ButtonX32.Click
        Clipboard.SetText(TextBoxX24.Text)
    End Sub
    Private Sub ButtonX31_Click(sender As Object, e As EventArgs) Handles ButtonX31.Click
        Clipboard.SetText(TextBoxX23.Text)
    End Sub
    Private Sub ButtonX57_Click(sender As Object, e As EventArgs) Handles ButtonX57.Click
        Clipboard.SetText(TextBoxX53.Text)
    End Sub
    Private Sub ButtonX58_Click(sender As Object, e As EventArgs) Handles ButtonX58.Click
        Clipboard.SetText(TextBoxX54.Text)
    End Sub
    Private Sub ButtonX59_Click(sender As Object, e As EventArgs) Handles ButtonX59.Click
        Clipboard.SetText(TextBoxX55.Text)
    End Sub
    Private Sub ButtonX60_Click(sender As Object, e As EventArgs) Handles ButtonX60.Click
        Clipboard.SetText(TextBoxX56.Text)
    End Sub
    Private Sub ButtonX61_Click(sender As Object, e As EventArgs) Handles ButtonX61.Click
        Clipboard.SetText(TextBoxX57.Text)
    End Sub
    Private Sub ButtonX62_Click(sender As Object, e As EventArgs) Handles ButtonX62.Click
        Clipboard.SetText(TextBoxX58.Text)
    End Sub
    Private Sub ButtonX63_Click(sender As Object, e As EventArgs) Handles ButtonX63.Click
        Clipboard.SetText(TextBoxX59.Text)
    End Sub
    Private Sub ButtonX65_Click(sender As Object, e As EventArgs) Handles ButtonX65.Click
        Clipboard.SetText(TextBoxX60.Text)
    End Sub
    Private Sub ButtonX66_Click(sender As Object, e As EventArgs) Handles ButtonX66.Click
        Clipboard.SetText(TextBoxX61.Text)
    End Sub
    Private Sub ButtonX67_Click(sender As Object, e As EventArgs) Handles ButtonX67.Click
        Clipboard.SetText(TextBoxX62.Text)
    End Sub
    Private Sub ButtonX68_Click(sender As Object, e As EventArgs) Handles ButtonX68.Click
        Clipboard.SetText(TextBoxX63.Text)
    End Sub
    Private Sub ButtonX69_Click(sender As Object, e As EventArgs) Handles ButtonX69.Click
        Clipboard.SetText(TextBoxX64.Text)
    End Sub
    Private Sub ButtonX70_Click(sender As Object, e As EventArgs) Handles ButtonX70.Click
        Clipboard.SetText(TextBoxX65.Text)
    End Sub
    Private Sub ButtonX71_Click(sender As Object, e As EventArgs) Handles ButtonX71.Click
        Clipboard.SetText(TextBoxX66.Text)
    End Sub
    Private Sub ButtonX72_Click(sender As Object, e As EventArgs) Handles ButtonX72.Click
        Clipboard.SetText(TextBoxX67.Text)
    End Sub
    Private Sub ButtonX73_Click(sender As Object, e As EventArgs) Handles ButtonX73.Click
        Clipboard.SetText(TextBoxX68.Text)
    End Sub
    Private Sub ButtonX74_Click(sender As Object, e As EventArgs) Handles ButtonX74.Click
        Clipboard.SetText(TextBoxX69.Text)
    End Sub
    Private Sub ButtonX75_Click(sender As Object, e As EventArgs) Handles ButtonX75.Click
        Clipboard.SetText(TextBoxX70.Text)
    End Sub
    Private Sub ButtonX76_Click(sender As Object, e As EventArgs) Handles ButtonX76.Click
        Clipboard.SetText(TextBoxX71.Text)
    End Sub
    Private Sub ButtonX77_Click(sender As Object, e As EventArgs) Handles ButtonX77.Click
        Clipboard.SetText(TextBoxX72.Text)
    End Sub
    Private Sub ButtonX78_Click(sender As Object, e As EventArgs) Handles ButtonX78.Click
        Clipboard.SetText(TextBoxX73.Text)
    End Sub
    Private Sub ButtonX79_Click(sender As Object, e As EventArgs) Handles ButtonX79.Click
        Clipboard.SetText(TextBoxX74.Text)
    End Sub
    Private Sub ButtonX80_Click(sender As Object, e As EventArgs) Handles ButtonX80.Click
        Clipboard.SetText(TextBoxX75.Text)
    End Sub
    Private Sub ButtonX81_Click(sender As Object, e As EventArgs) Handles ButtonX81.Click
        Clipboard.SetText(TextBoxX76.Text)
    End Sub
    Private Sub ButtonX82_Click(sender As Object, e As EventArgs) Handles ButtonX82.Click
        Clipboard.SetText(TextBoxX77.Text)
    End Sub
    Private Sub ButtonX30_Click(sender As Object, e As EventArgs) Handles ButtonX30.Click
        Clipboard.SetText(TextBoxX22.Text)
    End Sub
    Private Sub ButtonX29_Click(sender As Object, e As EventArgs) Handles ButtonX29.Click
        Clipboard.SetText(TextBoxX21.Text)
    End Sub
    Private Sub ButtonX28_Click(sender As Object, e As EventArgs) Handles ButtonX28.Click
        Clipboard.SetText(TextBoxX20.Text)
    End Sub
    Private Sub ButtonX27_Click(sender As Object, e As EventArgs) Handles ButtonX27.Click
        Clipboard.SetText(TextBoxX19.Text)
    End Sub
    Private Sub ButtonX26_Click(sender As Object, e As EventArgs) Handles ButtonX26.Click
        Clipboard.SetText(TextBoxX18.Text)
    End Sub
#End Region
#Region "randompoolshit"
    Private Sub TextBox47_MouseDoubleClick(sender As Object, e As MouseEventArgs) Handles TextBox47.MouseDoubleClick
        TextBox47.SelectAll()
    End Sub
    Private Sub RandomPool2_CharacterSelection(s As Object, c As Char) Handles RandomPool2.CharacterSelection
        Dim flag As Boolean = Me.TextBox47.TextLength < Me.NumericUpDown73.Value
        If flag Then
            Me.TextBox47.AppendText(Conversions.ToString(c))
        End If
        flag = (Me.NumericUpDown73.Value = 0)
        If flag Then
            Me.TextBox47.Text = ""
        End If
    End Sub
    Private Sub ButtonX86_Click(sender As Object, e As EventArgs) Handles ButtonX86.Click
        RandomPool2.RangePadding = NumericUpDown72.Value
    End Sub
    Private Sub ButtonX87_Click(sender As Object, e As EventArgs) Handles ButtonX87.Click
        Dim random As New Random
        If RadioButton18.Checked = True Then
            RandomPool2.Range = CryptString_1(random.Next)
        Else
        End If
        If RadioButton19.Checked = True Then
            RandomPool2.Range = Atom128_Encode(random.Next)
        Else
        End If
        If RadioButton20.Checked = True Then
            RandomPool2.Range = BASE64_Encode(random.Next)
        Else
        End If
        If RadioButton21.Checked = True Then
            RandomPool2.Range = ConvertToBinary(random.Next)
        Else
        End If
        If RadioButton22.Checked = True Then
            RandomPool2.Range = Zip_deflate(random.Next)
        Else
        End If
        If RadioButton23.Checked = True Then
            RandomPool2.Range = Zip_G(random.Next)
        Else
        End If
        If RadioButton24.Checked = True Then
            RandomPool2.Range = Encrypt_CustomLine(random.Next)
        Else
        End If
        If RadioButton25.Checked = True Then
            RandomPool2.Range = ESAB46_Encode(random.Next)
        Else
        End If
        If RadioButton26.Checked = True Then
            RandomPool2.Range = FERON74_Encode(random.Next)
        Else
        End If
        If RadioButton27.Checked = True Then
            RandomPool2.Range = GILA7_Encode(random.Next)
        Else
        End If
        If RadioButton28.Checked = True Then
            RandomPool2.Range = HAZZ15_Encode(random.Next)
        Else
        End If
        If RadioButton29.Checked = True Then
            RandomPool2.Range = String2Hex(random.Next)
        Else
        End If
        If RadioButton30.Checked = True Then
            RandomPool2.Range = MD5Hash(random.Next)
        Else
        End If
        If RadioButton31.Checked = True Then
            RandomPool2.Range = MEGAN35_Encode(random.Next)
        Else
        End If
        If RadioButton32.Checked = True Then
            RandomPool2.Range = pr0t3_encrypt(random.Next)
        Else
        End If
        If RadioButton33.Checked = True Then
            RandomPool2.Range = StrReverse(random.Next)
        Else
        End If
        If RadioButton34.Checked = True Then
            RandomPool2.Range = RIPEMD160Hash(random.Next)
        Else
        End If
        If RadioButton35.Checked = True Then
            RandomPool2.Range = Rot13(random.Next)
        Else
        End If
        If RadioButton36.Checked = True Then
            RandomPool2.Range = RSA_Encrypt(random.Next)
        Else
        End If
        If RadioButton37.Checked = True Then
            RandomPool2.Range = SHA1Hash(random.Next)
        Else
        End If
        If RadioButton38.Checked = True Then
            RandomPool2.Range = SHA256Hash(random.Next)
        Else
        End If
        If RadioButton39.Checked = True Then
            RandomPool2.Range = SHA348Hash(random.Next)
        Else
        End If
        If RadioButton40.Checked = True Then
            RandomPool2.Range = SHA512Hash(random.Next)
        Else
        End If
        If RadioButton41.Checked = True Then
            RandomPool2.Range = TIGO3FX_Encode(random.Next)
        Else
        End If
        If RadioButton42.Checked = True Then
            RandomPool2.Range = TRIPO5_Encode(random.Next)
        Else
        End If
        If RadioButton43.Checked = True Then
            RandomPool2.Range = ZARA128_Encode(random.Next)
        Else
        End If
        If RadioButton44.Checked = True Then
            RandomPool2.Range = ZONG22_Encode(random.Next)
        Else
        End If
        If RadioButton45.Checked = True Then
            RandomPool2.Range = HMACMD5(random.Next)
        Else
        End If
        If RadioButton46.Checked = True Then
            RandomPool2.Range = HMACRIPEMD160(random.Next)
        Else
        End If
        If RadioButton47.Checked = True Then
            RandomPool2.Range = HMACSHA1(random.Next)
        Else
        End If
        If RadioButton48.Checked = True Then
            RandomPool2.Range = HMACSHA256(random.Next)
        Else
        End If
        If RadioButton49.Checked = True Then
            RandomPool2.Range = HMACSHA384(random.Next)
        Else
        End If
        If RadioButton50.Checked = True Then
            RandomPool2.Range = HMACSHA512(random.Next)
        Else
        End If
        If RadioButton51.Checked = True Then
            RandomPool2.Range = MACTripleDES(random.Next)
        Else
        End If
        If RadioButton52.Checked = True Then
            RandomPool2.Range = EncryptSHA512Managed(random.Next)
        Else
        End If
    End Sub
    Private Sub ButtonX88_Click(sender As Object, e As EventArgs) Handles ButtonX88.Click
        RandomPool2.Range = TextBox46.Text
    End Sub
    Private Sub ButtonX90_Click(sender As Object, e As EventArgs) Handles ButtonX90.Click
        Timer3.Start()
    End Sub
    Private Sub ButtonX89_Click(sender As Object, e As EventArgs) Handles ButtonX89.Click
        Timer3.Stop()
    End Sub

    Private Sub RandomPool2_MouseHover(sender As Object, e As EventArgs) Handles RandomPool2.MouseHover
        If RadioButton124.Checked = True Then
            Dim random As New Random
            If RadioButton122.Checked = True Then
                RandomPool2.Range = CryptString_1(random.Next)
            Else
            End If
            If RadioButton121.Checked = True Then
                RandomPool2.Range = Atom128_Encode(random.Next)
            Else
            End If
            If RadioButton120.Checked = True Then
                RandomPool2.Range = BASE64_Encode(random.Next)
            Else
            End If
            If RadioButton119.Checked = True Then
                RandomPool2.Range = ConvertToBinary(random.Next)
            Else
            End If
            If RadioButton118.Checked = True Then
                RandomPool2.Range = Zip_deflate(random.Next)
            Else
            End If
            If RadioButton117.Checked = True Then
                RandomPool2.Range = Zip_G(random.Next)
            Else
            End If
            If RadioButton116.Checked = True Then
                RandomPool2.Range = Encrypt_CustomLine(random.Next)
            Else
            End If
            If RadioButton115.Checked = True Then
                RandomPool2.Range = ESAB46_Encode(random.Next)
            Else
            End If
            If RadioButton114.Checked = True Then
                RandomPool2.Range = FERON74_Encode(random.Next)
            Else
            End If
            If RadioButton113.Checked = True Then
                RandomPool2.Range = GILA7_Encode(random.Next)
            Else
            End If
            If RadioButton112.Checked = True Then
                RandomPool2.Range = HAZZ15_Encode(random.Next)
            Else
            End If
            If RadioButton111.Checked = True Then
                RandomPool2.Range = String2Hex(random.Next)
            Else
            End If
            If RadioButton110.Checked = True Then
                RandomPool2.Range = MD5Hash(random.Next)
            Else
            End If
            If RadioButton109.Checked = True Then
                RandomPool2.Range = MEGAN35_Encode(random.Next)
            Else
            End If
            If RadioButton108.Checked = True Then
                RandomPool2.Range = pr0t3_encrypt(random.Next)
            Else
            End If
            If RadioButton107.Checked = True Then
                RandomPool2.Range = StrReverse(random.Next)
            Else
            End If
            If RadioButton106.Checked = True Then
                RandomPool2.Range = RIPEMD160Hash(random.Next)
            Else
            End If
            If RadioButton105.Checked = True Then
                RandomPool2.Range = Rot13(random.Next)
            Else
            End If
            If RadioButton104.Checked = True Then
                RandomPool2.Range = RSA_Encrypt(random.Next)
            Else
            End If
            If RadioButton103.Checked = True Then
                RandomPool2.Range = SHA1Hash(random.Next)
            Else
            End If
            If RadioButton102.Checked = True Then
                RandomPool2.Range = SHA256Hash(random.Next)
            Else
            End If
            If RadioButton101.Checked = True Then
                RandomPool2.Range = SHA348Hash(random.Next)
            Else
            End If
            If RadioButton100.Checked = True Then
                RandomPool2.Range = SHA512Hash(random.Next)
            Else
            End If
            If RadioButton99.Checked = True Then
                RandomPool2.Range = TIGO3FX_Encode(random.Next)
            Else
            End If
            If RadioButton98.Checked = True Then
                RandomPool2.Range = TRIPO5_Encode(random.Next)
            Else
            End If
            If RadioButton97.Checked = True Then
                RandomPool2.Range = ZARA128_Encode(random.Next)
            Else
            End If
            If RadioButton96.Checked = True Then
                RandomPool2.Range = ZONG22_Encode(random.Next)
            Else
            End If
            If RadioButton95.Checked = True Then
                RandomPool2.Range = HMACMD5(random.Next)
            Else
            End If
            If RadioButton94.Checked = True Then
                RandomPool2.Range = HMACRIPEMD160(random.Next)
            Else
            End If
            If RadioButton93.Checked = True Then
                RandomPool2.Range = HMACSHA1(random.Next)
            Else
            End If
            If RadioButton92.Checked = True Then
                RandomPool2.Range = HMACSHA256(random.Next)
            Else
            End If
            If RadioButton91.Checked = True Then
                RandomPool2.Range = HMACSHA384(random.Next)
            Else
            End If
            If RadioButton90.Checked = True Then
                RandomPool2.Range = HMACSHA512(random.Next)
            Else
            End If
            If RadioButton89.Checked = True Then
                RandomPool2.Range = MACTripleDES(random.Next)
            Else
            End If
            If RadioButton88.Checked = True Then
                RandomPool2.Range = EncryptSHA512Managed(random.Next)
            Else
            End If
        End If
        If RadioButton123.Checked = True Then

        End If
    End Sub
    Private Sub RandomPool2_MouseClick(sender As Object, e As MouseEventArgs) Handles RandomPool2.MouseClick
        If RadioButton127.Checked = True Then
            Dim random As New Random
            If RadioButton125.Checked = True Then
                RandomPool2.Range = CryptString_1(random.Next)
            Else
            End If
            If RadioButton128.Checked = True Then
                RandomPool2.Range = Atom128_Encode(random.Next)
            Else
            End If
            If RadioButton130.Checked = True Then
                RandomPool2.Range = BASE64_Encode(random.Next)
            Else
            End If
            If RadioButton132.Checked = True Then
                RandomPool2.Range = ConvertToBinary(random.Next)
            Else
            End If
            If RadioButton134.Checked = True Then
                RandomPool2.Range = Zip_deflate(random.Next)
            Else
            End If
            If RadioButton136.Checked = True Then
                RandomPool2.Range = Zip_G(random.Next)
            Else
            End If
            If RadioButton138.Checked = True Then
                RandomPool2.Range = Encrypt_CustomLine(random.Next)
            Else
            End If
            If RadioButton140.Checked = True Then
                RandomPool2.Range = ESAB46_Encode(random.Next)
            Else
            End If
            If RadioButton142.Checked = True Then
                RandomPool2.Range = FERON74_Encode(random.Next)
            Else
            End If
            If RadioButton144.Checked = True Then
                RandomPool2.Range = GILA7_Encode(random.Next)
            Else
            End If
            If RadioButton146.Checked = True Then
                RandomPool2.Range = HAZZ15_Encode(random.Next)
            Else
            End If
            If RadioButton148.Checked = True Then
                RandomPool2.Range = String2Hex(random.Next)
            Else
            End If
            If RadioButton150.Checked = True Then
                RandomPool2.Range = MD5Hash(random.Next)
            Else
            End If
            If RadioButton152.Checked = True Then
                RandomPool2.Range = MEGAN35_Encode(random.Next)
            Else
            End If
            If RadioButton154.Checked = True Then
                RandomPool2.Range = pr0t3_encrypt(random.Next)
            Else
            End If
            If RadioButton156.Checked = True Then
                RandomPool2.Range = StrReverse(random.Next)
            Else
            End If
            If RadioButton158.Checked = True Then
                RandomPool2.Range = RIPEMD160Hash(random.Next)
            Else
            End If
            If RadioButton160.Checked = True Then
                RandomPool2.Range = Rot13(random.Next)
            Else
            End If
            If RadioButton161.Checked = True Then
                RandomPool2.Range = RSA_Encrypt(random.Next)
            Else
            End If
            If RadioButton159.Checked = True Then
                RandomPool2.Range = SHA1Hash(random.Next)
            Else
            End If
            If RadioButton157.Checked = True Then
                RandomPool2.Range = SHA256Hash(random.Next)
            Else
            End If
            If RadioButton155.Checked = True Then
                RandomPool2.Range = SHA348Hash(random.Next)
            Else
            End If
            If RadioButton153.Checked = True Then
                RandomPool2.Range = SHA512Hash(random.Next)
            Else
            End If
            If RadioButton151.Checked = True Then
                RandomPool2.Range = TIGO3FX_Encode(random.Next)
            Else
            End If
            If RadioButton149.Checked = True Then
                RandomPool2.Range = TRIPO5_Encode(random.Next)
            Else
            End If
            If RadioButton147.Checked = True Then
                RandomPool2.Range = ZARA128_Encode(random.Next)
            Else
            End If
            If RadioButton145.Checked = True Then
                RandomPool2.Range = ZONG22_Encode(random.Next)
            Else
            End If
            If RadioButton143.Checked = True Then
                RandomPool2.Range = HMACMD5(random.Next)
            Else
            End If
            If RadioButton141.Checked = True Then
                RandomPool2.Range = HMACRIPEMD160(random.Next)
            Else
            End If
            If RadioButton139.Checked = True Then
                RandomPool2.Range = HMACSHA1(random.Next)
            Else
            End If
            If RadioButton137.Checked = True Then
                RandomPool2.Range = HMACSHA256(random.Next)
            Else
            End If
            If RadioButton135.Checked = True Then
                RandomPool2.Range = HMACSHA384(random.Next)
            Else
            End If
            If RadioButton133.Checked = True Then
                RandomPool2.Range = HMACSHA512(random.Next)
            Else
            End If
            If RadioButton131.Checked = True Then
                RandomPool2.Range = MACTripleDES(random.Next)
            Else
            End If
            If RadioButton129.Checked = True Then
                RandomPool2.Range = EncryptSHA512Managed(random.Next)
            Else
            End If
        End If
        If RadioButton126.Checked = True Then

        End If
    End Sub
#End Region
#Region "PastebinAPI"
    Public Shared Function GetPasteText(ByVal PasteKey As String) As String
        With New WebClient
            Dim html As String = .DownloadString("http://pastebin.com/raw.php?i=" & PasteKey)
            Return html
        End With
    End Function
    Public Function Raw(ByVal URL As String)
        Dim ID As String = URL.Substring(URL.LastIndexOf("/") + 1)
        ID = "http://pastebin.com/raw.php?i=" & ID
        Return ID
    End Function
    Private Sub ButtonX83_Click(sender As Object, e As EventArgs) Handles ButtonX83.Click
        Dim Maker As New Paste(TextBox177.Text, TextBox171.Text, TextBox172.Text, TextBox169.Text,
                               TextBox173.Text, NumericUpDown74.Value, TextBox174.Text, TextBox175.Text)
        Maker.Start()
    End Sub
    Private Sub ButtonX85_Click(sender As Object, e As EventArgs) Handles ButtonX85.Click
        Pastebin.Username = TextBox171.Text
        Pastebin.Password = TextBox172.Text
    End Sub
    Private Sub LinkLabel1_LinkClicked(sender As Object, e As LinkLabelLinkClickedEventArgs) Handles LinkLabel1.LinkClicked
        Process.Start("https://pastebin.com/api")
    End Sub
#End Region
    Private Sub PictureBox13_Click(sender As Object, e As EventArgs) Handles PictureBox13.Click
        Dim Save As New Windows.Forms.SaveFileDialog()
        Dim myStreamWriter As StreamWriter
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Save Text as..."
        Save.ShowDialog(Me)
        Try
            myStreamWriter = File.AppendText(Save.FileName)
            myStreamWriter.Write(Logintextbox1.Text)
            myStreamWriter.Flush()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub ButtonX91_Click(sender As Object, e As EventArgs) Handles ButtonX91.Click

    End Sub

    Private Sub Command1_Executed(sender As Object, e As EventArgs) Handles Command1.Executed
        Dim source As ICommandSource = CType(sender, ICommandSource)
        If TypeOf (source.CommandParameter) Is String Then
            Dim cs As DevComponents.DotNetBar.eStyle = CType(System.Enum.Parse(GetType(eStyle), source.CommandParameter.ToString()), eStyle)
            StyleManager.ChangeStyle(cs, Color.Empty)
        ElseIf TypeOf (source.CommandParameter) Is Color Then
            StyleManager.ColorTint = CType(source.CommandParameter, Color)
        End If
    End Sub

    Private Sub PictureBox14_Click(sender As Object, e As EventArgs) Handles PictureBox14.Click
        Dim Save As New Windows.Forms.OpenFileDialog()
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Open..."
        Save.ShowDialog(Me)
        Try
            Dim sr As New IO.StreamReader(Save.FileName)

            Logintextbox1.Text = sr.ReadToEnd()

            sr.Close()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub PictureBox15_Click(sender As Object, e As EventArgs) Handles PictureBox15.Click
        Dim Save As New Windows.Forms.OpenFileDialog()
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Open..."
        Save.ShowDialog(Me)
        Try
            Dim sr As New IO.StreamReader(Save.FileName)

            TextBox4.Text = sr.ReadToEnd()

            sr.Close()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub PictureBox16_Click(sender As Object, e As EventArgs) Handles PictureBox16.Click
        Dim Save As New Windows.Forms.SaveFileDialog()
        Dim myStreamWriter As StreamWriter
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Save Text as..."
        Save.ShowDialog(Me)
        Try
            myStreamWriter = File.AppendText(Save.FileName)
            myStreamWriter.Write(TextBox4.Text)
            myStreamWriter.Flush()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub PictureBox17_Click(sender As Object, e As EventArgs) Handles PictureBox17.Click
        Dim Save As New Windows.Forms.OpenFileDialog()
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Open..."
        Save.ShowDialog(Me)
        Try
            Dim sr As New IO.StreamReader(Save.FileName)

            TextBox8.Text = sr.ReadToEnd()

            sr.Close()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub PictureBox18_Click(sender As Object, e As EventArgs) Handles PictureBox18.Click
        Dim Save As New Windows.Forms.SaveFileDialog()
        Dim myStreamWriter As StreamWriter
        Save.Filter = "Text [*.txt*]|*.txt|All files [*.*]|*.*"
        Save.CheckPathExists = True
        Save.Title = "Save Text as..."
        Save.ShowDialog(Me)
        Try
            myStreamWriter = File.AppendText(Save.FileName)
            myStreamWriter.Write(TextBox8.Text)
            myStreamWriter.Flush()
        Catch ex As Exception
        End Try
    End Sub

    Private Sub ButtonX16_Click(sender As Object, e As EventArgs) Handles ButtonX16.Click
        Dim r As New Random
        Logintextbox1.Text = New String(Logintextbox1.Text.ToCharArray.OrderBy(Function(c) r.NextDouble).ToArray)
    End Sub

    Private Sub ButtonX105_Click(sender As Object, e As EventArgs) Handles ButtonX105.Click
        Dim colordialog1 As New ColorDialog
        If colordialog1.ShowDialog() = Windows.Forms.DialogResult.OK Then
            Dim conv As New ColorConverter
            Dim c As Color = colordialog1.Color
            Dim s As String = conv.ConvertToString(c)
            Dim h As String = Hex(c.ToArgb)
            Dim r As String = String.Empty
            Dim g As String = String.Empty
            Dim b As String = String.Empty
            Try
                r = c.R.ToString()
                g = c.G.ToString()
                b = c.B.ToString()
                TextBox10.Text = r & ", " + g & ", " + b
                TextBox170.Text = "#" + h
                PictureBox19.BackColor = c
            Catch ex As Exception

            End Try


        End If
    End Sub
    <DllImport("user32.dll")>
    Private Shared Function GetDC(hwnd As IntPtr) As IntPtr
    End Function

    <DllImport("user32.dll")>
    Private Shared Function ReleaseDC(hwnd As IntPtr, hdc As IntPtr) As Int32
    End Function

    <DllImport("gdi32.dll")>
    Private Shared Function GetPixel(hdc As IntPtr, nXPos As Integer, nYPos As Integer) As UInteger
    End Function
    Public Function GetPixelColor(x As Integer, y As Integer) As System.Drawing.Color
        Dim hdc As IntPtr = GetDC(IntPtr.Zero)
        Dim pixel As UInteger = GetPixel(hdc, x, y)
        ReleaseDC(IntPtr.Zero, hdc)
        Dim color__1 As Color = Color.FromArgb(CInt(pixel And &HFF), CInt(pixel And &HFF00) >> 8, CInt(pixel And &HFF0000) >> 16)
        Return color__1
    End Function


    Private Sub PictureBox19_Click(sender As Object, e As EventArgs) Handles PictureBox19.Click

    End Sub

    Private Sub Timer6_Tick(sender As Object, e As EventArgs) Handles Timer6.Tick
        Dim CurrentColor As Color = GetPixelColor(Cursor.Position.X, Cursor.Position.Y)
        PictureBox19.BackColor = CurrentColor
        Dim r As String = String.Empty
        Dim g As String = String.Empty
        Dim b As String = String.Empty
        Dim h As String = Hex(CurrentColor.ToArgb)
        Try
            r = CurrentColor.R.ToString()
            g = CurrentColor.G.ToString()
            b = CurrentColor.B.ToString()
            TextBox10.Text = r & ", " + g & ", " + b
            TextBox170.Text = "#" + h
        Catch ex As Exception

        End Try


    End Sub

    Private Sub CheckBoxX3_CheckedChanged(sender As Object, e As EventArgs) Handles CheckBoxX3.CheckedChanged
        If CheckBoxX3.Checked = True Then
            Timer6.Start()
        Else
            Timer6.Stop()
        End If
    End Sub

    Private Sub JamesrebornsProtections_KeyDown(sender As Object, e As KeyEventArgs) Handles MyBase.KeyDown
        If e.KeyCode = Keys.Escape Then
            CheckBoxX3.CheckState = CheckState.Unchecked
        End If
    End Sub

    Private Sub ButtonX106_Click(sender As Object, e As EventArgs)

    End Sub

    Private Sub TextBoxX78_MouseMove(sender As Object, e As MouseEventArgs)

    End Sub

    Private Sub Logintextbox1_TextChanged(sender As Object, e As EventArgs) Handles Logintextbox1.TextChanged, txtHexadecimal.TextChanged, txtOctal.TextChanged
        DisplayValue(sender)
    End Sub

    Private Sub txtHexadecimal_MouseDoubleClick(sender As Object, e As MouseEventArgs) Handles txtHexadecimal.MouseDoubleClick
        txtHexadecimal.SelectAll()
        Dim textty As String = txtHexadecimal.Text
        Clipboard.SetText(textty)
    End Sub

End Class