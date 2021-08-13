Imports System
Imports System.Diagnostics
Imports System.IO
Imports System.IO.Compression
Imports System.Security.Cryptography
Imports System.Text
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices

Namespace algorithmslist
    Public Class algorithms
        ' Token: 0x0200000A RID: 10
        <DebuggerNonUserCode()>
        Public Sub New()
        End Sub

        Public Shared Function Md5Encrypt(bytData As Byte(), sKey As String, Optional tMode As CipherMode = CipherMode.ECB, Optional tPadding As PaddingMode = PaddingMode.PKCS7) As Byte()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim key As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(sKey))
            mD5CryptoServiceProvider.Clear()
            Dim tripleDESCryptoServiceProvider As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider() With {.Key = key, .Mode = tMode, .Padding = tPadding}
            Dim result As Byte() = tripleDESCryptoServiceProvider.CreateEncryptor().TransformFinalBlock(bytData, 0, bytData.Length)
            tripleDESCryptoServiceProvider.Clear()
            Return result
        End Function

        Public Shared Function RC2Encrypt(strInput As String, strPassword As String) As String
            Dim rC2CryptoServiceProvider As RC2CryptoServiceProvider = New RC2CryptoServiceProvider()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim result As String
            Try
                Dim key As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(strPassword))
                rC2CryptoServiceProvider.Key = key
                rC2CryptoServiceProvider.Mode = CipherMode.ECB
                Dim cryptoTransform As ICryptoTransform = rC2CryptoServiceProvider.CreateEncryptor()
                Dim bytes As Byte() = Encoding.ASCII.GetBytes(strInput)
                Dim text As String = Convert.ToBase64String(cryptoTransform.TransformFinalBlock(bytes, 0, bytes.Length))
                result = text
            Catch expr_67 As Exception
                ProjectData.SetProjectError(expr_67)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function AES_Encrypt(input As String, pass As String) As String
            Dim rijndaelManaged As RijndaelManaged = New RijndaelManaged()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim result As String
            Try
                Dim array As Byte() = New Byte(31) {}
                Dim sourceArray As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(pass))
                array.Copy(sourceArray, 0, array, 0, 16)
                array.Copy(sourceArray, 0, array, 15, 16)
                rijndaelManaged.Key = array
                rijndaelManaged.Mode = CipherMode.ECB
                Dim cryptoTransform As ICryptoTransform = rijndaelManaged.CreateEncryptor()
                Dim bytes As Byte() = Encoding.ASCII.GetBytes(input)
                Dim text As String = Convert.ToBase64String(cryptoTransform.TransformFinalBlock(bytes, 0, bytes.Length))
                result = text
            Catch expr_8D As Exception
                ProjectData.SetProjectError(expr_8D)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function TripleDES_Encrypt(input As String, pass As String) As String
            Dim tripleDESCryptoServiceProvider As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim result As String
            Try
                Dim array As Byte() = New Byte(23) {}
                Dim sourceArray As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(pass))
                array.Copy(sourceArray, 0, array, 0, 16)
                array.Copy(sourceArray, 0, array, 15, 8)
                tripleDESCryptoServiceProvider.Key = array
                tripleDESCryptoServiceProvider.Mode = CipherMode.ECB
                Dim cryptoTransform As ICryptoTransform = tripleDESCryptoServiceProvider.CreateEncryptor()
                Dim bytes As Byte() = Encoding.ASCII.GetBytes(input)
                Dim text As String = Convert.ToBase64String(cryptoTransform.TransformFinalBlock(bytes, 0, bytes.Length))
                result = text
            Catch expr_8C As Exception
                ProjectData.SetProjectError(expr_8C)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function XOR_Encrypt(Input As String, pass As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim arg_12_0 As Integer = 0
            ' The following expression was wrapped in a checked-statement
            Dim num As Integer = Input.Length - 1
            Dim num2 As Integer = arg_12_0
            While True
                Dim arg_82_0 As Integer = num2
                Dim num3 As Integer = num
                If arg_82_0 > num3 Then
                    Exit While
                End If
                Dim num4 As Integer
                Dim text As String = Conversion.Hex(Strings.Asc(Input(num2)) Xor Strings.Asc(pass(num4)))
                Dim flag As Boolean = text.Length = 1
                If flag Then
                    text = "0" + text
                End If
                stringBuilder.Append(text)
                flag = (num4 = pass.Length - 1)
                If flag Then
                    num4 = 0
                Else
                    num4 += 1
                End If
                num2 += 1
            End While
            Return stringBuilder.ToString()
        End Function

        Public Shared Function Rijndaelcrypt(File As String, Key As String) As Object
            Dim rijndaelManaged As RijndaelManaged = New RijndaelManaged()
            Dim salt As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
            Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(Key, salt)
            rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.Key.Length)
            rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.IV.Length)
            Dim memoryStream As MemoryStream = New MemoryStream()
            Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write)
            Dim bytes As Byte() = Encoding.UTF8.GetBytes(File)
            cryptoStream.Write(bytes, 0, bytes.Length)
            cryptoStream.Close()
            File = Convert.ToBase64String(memoryStream.ToArray())
            Return File
        End Function

        Public Shared Function DES_Encrypt(input As String, pass As String) As String
            Dim dESCryptoServiceProvider As DESCryptoServiceProvider = New DESCryptoServiceProvider()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim result As String
            Try
                Dim array As Byte() = New Byte(7) {}
                Dim sourceArray As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(pass))
                array.Copy(sourceArray, 0, array, 0, 8)
                dESCryptoServiceProvider.Key = array
                dESCryptoServiceProvider.Mode = CipherMode.ECB
                Dim cryptoTransform As ICryptoTransform = dESCryptoServiceProvider.CreateEncryptor()
                Dim bytes As Byte() = Encoding.ASCII.GetBytes(input)
                Dim text As String = Convert.ToBase64String(cryptoTransform.TransformFinalBlock(bytes, 0, bytes.Length))
                result = text
            Catch expr_7C As Exception
                ProjectData.SetProjectError(expr_7C)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function Encrypt(cipherTxt As String, key As String) As Object
            Dim text As String = ""
            Dim length As Integer = cipherTxt.Length
            ' The following expression was wrapped in a checked-statement
            For i As Integer = 1 To length
                Dim charCode As Integer = Strings.Asc(Strings.GetChar(cipherTxt, i)) + Strings.Asc(Strings.GetChar(key, i Mod key.Length + 1))
                text += Convert.ToString(Strings.Chr(charCode))
            Next
            Return text
        End Function

        Public Shared Function x(system As String, key As String) As String
            Dim num As Integer = Strings.Len(key)
            ' The following expression was wrapped in a checked-statement
            Dim num2 As Integer
            For i As Integer = 1 To num
                num2 += Strings.AscW(Strings.Mid(key, i, 1))
            Next
            Dim num3 As Integer = Strings.Len(system)
            Dim text As String
            For i As Integer = 1 To num3
                Dim charCode As Integer = Strings.AscW(Strings.Mid(system, i, 1)) + num2 Mod 1000
                text += Convert.ToString(Strings.ChrW(charCode))
            Next
            Return text
        End Function

        Public Shared Function Encryptvg(proj As String, key As String) As Object
            Dim text As String = ""
            Dim arg_10_0 As Integer = 1
            Dim length As Integer = proj.Length
            Dim num As Integer = arg_10_0
            ' The following expression was wrapped in a checked-statement
            While True
                Dim arg_4A_0 As Integer = num
                Dim num2 As Integer = length
                If arg_4A_0 > num2 Then
                    Exit While
                End If
                Dim charCode As Integer = CInt((Strings.GetChar(proj, num) + Strings.GetChar(key, num Mod key.Length + 1)))
                text += Conversions.ToString(Strings.ChrW(charCode))
                num += 1
            End While
            Return text
        End Function

        Public Shared Function String2Hex(input As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim i As Integer = 0
            Dim length As Integer = input.Length
            ' The following expression was wrapped in a checked-statement
            While i < length
                Dim [string] As String = Conversions.ToString(input(i))
                Dim str As String = Conversion.Hex(Strings.Asc([string]))
                stringBuilder.Append(str + " ")
                i += 1
            End While
            Return stringBuilder.ToString().Substring(0, stringBuilder.Length - 1)
        End Function

        Public Shared Function Zip_G(text As String) As String
            Dim bytes As Byte() = Encoding.Unicode.GetBytes(text)
            Dim memoryStream As MemoryStream = New MemoryStream()
            Dim gZipStream As GZipStream = New GZipStream(memoryStream, CompressionMode.Compress, True)
            Try
                gZipStream.Write(bytes, 0, bytes.Length)
            Finally
                Dim flag As Boolean = gZipStream IsNot Nothing
                If flag Then
                    CType(gZipStream, IDisposable).Dispose()
                End If
            End Try
            memoryStream.Position = 0L
            Dim memoryStream2 As MemoryStream = New MemoryStream()
            ' The following expression was wrapped in a checked-statement
            Dim array As Byte() = New Byte(CInt((memoryStream.Length - 1L)) + 1 - 1) {}
            memoryStream.Read(array, 0, array.Length)
            Dim array2 As Byte() = New Byte(array.Length + 3 + 1 - 1) {}
            Buffer.BlockCopy(array, 0, array2, 4, array.Length)
            Buffer.BlockCopy(BitConverter.GetBytes(bytes.Length), 0, array2, 0, 4)
            Return Convert.ToBase64String(array2)
        End Function

        Public Shared Function RC4Encrypt(A6 As Byte(), A7 As String) As Byte()
            Dim bytes As Byte() = Encoding.ASCII.GetBytes(A7)
            Dim array As UInteger() = New UInteger(255) {}
            ' The following expression was wrapped in a checked-statement
            Dim array2 As Byte() = New Byte(A6.Length - 1 + 1 - 1) {}
            Dim num As UInteger = 0UI
            Dim arg_3E_0 As UInteger
            Dim num2 As UInteger
            Do
                array(CInt(num)) = num
                num += 1UI
                arg_3E_0 = num
                num2 = 255UI
            Loop While arg_3E_0 <= num2
            num = 0UI
            Dim num3 As UInteger
            Dim arg_83_0 As UInteger
            Do
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a checked-expression
                ' The following expression was wrapped in a unchecked-expression
                num3 = CUInt((CULng((num3 + CUInt(bytes(CInt((CULng(num) Mod CULng(CLng(bytes.Length)))))) + array(CInt(num)))) And 255UL))
                Dim num4 As UInteger = array(CInt(num))
                array(CInt(num)) = array(CInt(num3))
                array(CInt(num3)) = num4
                num += 1UI
                arg_83_0 = num
                num2 = 255UI
            Loop While arg_83_0 <= num2
            num = 0UI
            num3 = 0UI
            Dim arg_92_0 As Integer = 0
            Dim num5 As Integer = array2.Length - 1
            Dim num6 As Integer = arg_92_0
            While True
                Dim arg_FC_0 As Integer = num6
                Dim num7 As Integer = num5
                If arg_FC_0 > num7 Then
                    Exit While
                End If
                ' The following expression was wrapped in a unchecked-expression
                num = CUInt((CULng(num) + 1UL And 255UL))
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a checked-expression
                num3 = CUInt((CULng((num3 + array(CInt(num)))) And 255UL))
                Dim num4 As UInteger = array(CInt(num))
                array(CInt(num)) = array(CInt(num3))
                array(CInt(num3)) = num4
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a checked-expression
                array2(num6) = CByte((CUInt(A6(num6)) Xor array(CInt((CULng((array(CInt(num)) + array(CInt(num3)))) And 255UL)))))
                num6 += 1
            End While
            Return array2
        End Function

        Public Shared Function EnC(data As Byte(), PP As String) As Byte()
            Dim stairsEncryption As algorithms.StairsEncryption = New algorithms.StairsEncryption()
            Return algorithms.StairsEncryption.Crypt(data, Encoding.[Default].GetBytes(PP))
        End Function

        Public Shared Function RSMEncrypt(data As Byte(), key As Byte()) As Byte()
            Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(key, New Byte(7) {}, 1)
            Dim rijndaelManaged As RijndaelManaged = New RijndaelManaged()
            rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(16)
            rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(16)
            ' The following expression was wrapped in a checked-expression
            Dim array As Byte() = New Byte(data.Length + 15 + 1 - 1) {}
            Buffer.BlockCopy(Guid.NewGuid().ToByteArray(), 0, array, 0, 16)
            Buffer.BlockCopy(data, 0, array, 16, data.Length)
            Return rijndaelManaged.CreateEncryptor().TransformFinalBlock(array, 0, array.Length)
        End Function

        Public Shared Function RSM(Files As Byte(), k As String) As Byte()
            Return algorithms.RSMEncrypt(Files, Encoding.[Default].GetBytes(k))
        End Function

        Public Shared Function EnCr(data As Byte(), PP As String) As Byte()
            Dim polyMorphicStairs As algorithms.PolyMorphicStairs = New algorithms.PolyMorphicStairs()
            Return algorithms.PolyMorphicStairs.PolyCrypt(data, Encoding.[Default].GetBytes(PP), 0UI)
        End Function

        Public Shared Function pr0t3_encrypt(message As String) As Object
            Dim num As Integer = 3
            message = Strings.StrReverse(message)
            Dim text As String = message
            Dim i As Integer = 0
            Dim length As Integer = text.Length
            ' The following expression was wrapped in a checked-statement
            Dim text2 As String
            While i < length
                Dim [string] As Char = text(i)
                text2 += Convert.ToString(Strings.Chr(Strings.Asc([string]) + num))
                i += 1
            End While
            Return text2
        End Function

        Public Shared Function Zip_deflate(text As String) As String
            Dim bytes As Byte() = Encoding.Unicode.GetBytes(text)
            Dim memoryStream As MemoryStream = New MemoryStream()
            Dim deflateStream As DeflateStream = New DeflateStream(memoryStream, CompressionMode.Compress, True)
            Try
                deflateStream.Write(bytes, 0, bytes.Length)
            Finally
                Dim flag As Boolean = deflateStream IsNot Nothing
                If flag Then
                    CType(deflateStream, IDisposable).Dispose()
                End If
            End Try
            memoryStream.Position = 0L
            Dim memoryStream2 As MemoryStream = New MemoryStream()
            ' The following expression was wrapped in a checked-statement
            Dim array As Byte() = New Byte(CInt((memoryStream.Length - 1L)) + 1 - 1) {}
            memoryStream.Read(array, 0, array.Length)
            Dim array2 As Byte() = New Byte(array.Length + 3 + 1 - 1) {}
            Buffer.BlockCopy(array, 0, array2, 4, array.Length)
            Buffer.BlockCopy(BitConverter.GetBytes(bytes.Length), 0, array2, 0, 4)
            Return Convert.ToBase64String(array2)
        End Function

        Public Shared Function ConvertToBinary(str As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim bytes As Byte() = Encoding.ASCII.GetBytes(str)
            ' The following expression was wrapped in a checked-statement
            For i As Integer = 0 To bytes.Length - 1
                Dim value As Byte = bytes(i)
                stringBuilder.Append(Convert.ToString(value, 2).PadLeft(8, "0"c))
            Next
            Return stringBuilder.ToString()
        End Function

        Public Class StairsEncryption
            ' Token: 0x0200000B RID: 11
            <DebuggerNonUserCode()>
            Public Sub New()
            End Sub

            Public Shared Function Crypt(Data As Byte(), key As Byte()) As Byte()
                Dim arg_0C_0 As Integer = 0
                ' The following expression was wrapped in a checked-statement
                Dim num As Integer = Data.Length * 2 + key.Length
                Dim num2 As Integer = arg_0C_0
                While True
                    Dim arg_3F_0 As Integer = num2
                    Dim num3 As Integer = num
                    If arg_3F_0 > num3 Then
                        Exit While
                    End If
                    Data(num2 Mod Data.Length) = (CByte((CInt((Data(num2 Mod Data.Length) + Data((num2 + 1) Mod Data.Length))) Mod 256)) Xor key(num2 Mod key.Length))
                    num2 += 1
                End While
                Return Data
            End Function
        End Class

        Public Class PolyMorphicStairs
            ' Token: 0x0200000C RID: 12
            <DebuggerNonUserCode()>
            Public Sub New()
            End Sub

            Public Shared Function PolyCrypt(ByRef Data As Byte(), Key As Byte(), Optional ExtraRounds As UInteger = 0UI) As Byte()
                ' The following expression was wrapped in a checked-statement
                Array.Resize(Of Byte)(Data, Data.Length + 1)
                Data(Data.Length - 1) = Convert.ToByte(New Random().[Next](1, 255))
                Dim num As Long = CLng((Data.Length - 1)) * CLng((CULng(ExtraRounds) + 1UL))
                While True
                    Dim arg_7D_0 As Long = num
                    Dim num2 As Long = 0L
                    If arg_7D_0 < num2 Then
                        Exit While
                    End If
                    ' The following expression was wrapped in a unchecked-expression
                    ' The following expression was wrapped in a unchecked-expression
                    ' The following expression was wrapped in a unchecked-expression
                    ' The following expression was wrapped in a unchecked-expression
                    Data(CInt((num Mod CLng(Data.Length)))) = (CByte((CInt((Data(CInt((num Mod CLng(Data.Length)))) + Data(CInt(((num + 1L) Mod CLng(Data.Length)))))) Mod 256)) Xor Key(CInt((num Mod CLng(Key.Length)))))
                    num += -1L
                End While
                Return Data
            End Function
        End Class
    End Class
End Namespace
