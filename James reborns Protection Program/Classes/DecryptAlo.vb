Imports System
Imports System.Diagnostics
Imports System.IO
Imports System.IO.Compression
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.RegularExpressions
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices

Namespace decrypts
    Public Class DecryptAlo
        ' Token: 0x02000016 RID: 22
        <DebuggerNonUserCode()>
        Public Sub New()
        End Sub

        Public Shared Function XOR_Decrypt(Input As String, pass As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim arg_12_0 As Integer = 0
            ' The following expression was wrapped in a checked-statement
            Dim num As Integer = Input.Length - 1
            Dim num2 As Integer = arg_12_0
            While True
                Dim arg_76_0 As Integer = num2
                Dim num3 As Integer = num
                If arg_76_0 > num3 Then
                    Exit While
                End If
                Dim num4 As Integer
                ' The following expression was wrapped in a unchecked-expression
                Dim value As String = Conversions.ToString(Strings.Chr(CInt((Conversions.ToLong("&H" + Input.Substring(num2, 2)) Xor CLng(Strings.Asc(pass(num4)))))))
                stringBuilder.Append(value)
                Dim flag As Boolean = num4 = pass.Length - 1
                If flag Then
                    num4 = 0
                Else
                    num4 += 1
                End If
                num2 += 2
            End While
            Return stringBuilder.ToString()
        End Function

        Public Shared Function RC2Decrypt(strInput As String, strPassword As String) As String
            Dim rC2CryptoServiceProvider As RC2CryptoServiceProvider = New RC2CryptoServiceProvider()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Try
            Catch expr_17 As Exception
                ProjectData.SetProjectError(expr_17)
                ProjectData.ClearProjectError()
            End Try
            Dim result As String
            Return result
        End Function

        Public Shared Function AES_Decrypt(input As String, pass As String) As String
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
                Dim cryptoTransform As ICryptoTransform = rijndaelManaged.CreateDecryptor()
                Dim array2 As Byte() = Convert.FromBase64String(input)
                Dim [string] As String = Encoding.ASCII.GetString(cryptoTransform.TransformFinalBlock(array2, 0, array2.Length))
                result = [string]
            Catch expr_8D As Exception
                ProjectData.SetProjectError(expr_8D)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function DES_Decrypt(input As String, pass As String) As String
            Dim dESCryptoServiceProvider As DESCryptoServiceProvider = New DESCryptoServiceProvider()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim result As String
            Try
                Dim array As Byte() = New Byte(7) {}
                Dim sourceArray As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(pass))
                array.Copy(sourceArray, 0, array, 0, 8)
                dESCryptoServiceProvider.Key = array
                dESCryptoServiceProvider.Mode = CipherMode.ECB
                Dim cryptoTransform As ICryptoTransform = dESCryptoServiceProvider.CreateDecryptor()
                Dim array2 As Byte() = Convert.FromBase64String(input)
                Dim [string] As String = Encoding.ASCII.GetString(cryptoTransform.TransformFinalBlock(array2, 0, array2.Length))
                result = [string]
            Catch expr_7C As Exception
                ProjectData.SetProjectError(expr_7C)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function Hex2String(input As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim array As String() = Strings.Split(input, " ", -1, CompareMethod.Binary)
            Dim array2 As String() = array
            ' The following expression was wrapped in a checked-statement
            For i As Integer = 0 To array2.Length - 1
                Dim str As String = array2(i)
                stringBuilder.Append(Strings.Chr(Conversions.ToInteger("&H" + str)))
            Next
            Return stringBuilder.ToString()
        End Function

        Public Shared Function TripleDES_Decrypt(input As String, pass As String) As String
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
                Dim cryptoTransform As ICryptoTransform = tripleDESCryptoServiceProvider.CreateDecryptor()
                Dim array2 As Byte() = Convert.FromBase64String(input)
                Dim [string] As String = Encoding.ASCII.GetString(cryptoTransform.TransformFinalBlock(array2, 0, array2.Length))
                result = [string]
            Catch expr_8C As Exception
                ProjectData.SetProjectError(expr_8C)
                ProjectData.ClearProjectError()
            End Try
            Return result
        End Function

        Public Shared Function Vernam(system As String, key As String) As String
            Dim arg_0A_0 As Integer = 1
            Dim num As Integer = Strings.Len(key)
            Dim num2 As Integer = arg_0A_0
            ' The following expression was wrapped in a checked-statement
            Dim num4 As Integer
            While True
                Dim arg_29_0 As Integer = num2
                Dim num3 As Integer = num
                If arg_29_0 > num3 Then
                    Exit While
                End If
                num4 += Strings.AscW(Strings.Mid(key, num2, 1))
                num2 += 1
            End While
            Dim arg_34_0 As Integer = 1
            Dim num5 As Integer = Strings.Len(system)
            num2 = arg_34_0
            Dim text As String
            While True
                Dim arg_6B_0 As Integer = num2
                Dim num3 As Integer = num5
                If arg_6B_0 > num3 Then
                    Exit While
                End If
                Dim charCode As Integer = Strings.AscW(Strings.Mid(system, num2, 1)) - num4 Mod 5555
                text += Conversions.ToString(Strings.ChrW(charCode))
                num2 += 1
            End While
            Return text
        End Function

        Public Shared Function ConvertToAscii(str As String) As String
            Dim text As String = Regex.Replace(str, "[^01]", "")
            ' The following expression was wrapped in a checked-statement
            Dim array As Byte() = New Byte(CInt(Math.Round(CDbl(text.Length) / 8.0 - 1.0)) + 1 - 1) {}
            Dim arg_43_0 As Integer = 0
            Dim num As Integer = array.Length - 1
            Dim num2 As Integer = arg_43_0
            While True
                Dim arg_65_0 As Integer = num2
                Dim num3 As Integer = num
                If arg_65_0 > num3 Then
                    Exit While
                End If
                array(num2) = Convert.ToByte(text.Substring(num2 * 8, 8), 2)
                num2 += 1
            End While
            Return Encoding.ASCII.GetString(array)
        End Function


        Public Shared Function UnZip_G(compressedText As String) As String
            Dim array As Byte() = Convert.FromBase64String(compressedText)
            Dim memoryStream As MemoryStream = New MemoryStream()
            ' The following expression was wrapped in a checked-statement
            Dim [string] As String
            Try
                Dim num As Integer = BitConverter.ToInt32(array, 0)
                memoryStream.Write(array, 4, array.Length - 4)
                Dim array2 As Byte() = New Byte(num - 1 + 1 - 1) {}
                memoryStream.Position = 0L
                Dim gZipStream As GZipStream = New GZipStream(memoryStream, CompressionMode.Decompress)
                Try
                    gZipStream.Read(array2, 0, array2.Length)
                Finally
                    Dim flag As Boolean = gZipStream IsNot Nothing
                    If flag Then
                        CType(gZipStream, IDisposable).Dispose()
                    End If
                End Try
                [string] = Encoding.Unicode.GetString(array2, 0, array2.Length)
            Finally
                Dim flag As Boolean = memoryStream IsNot Nothing
                If flag Then
                    CType(memoryStream, IDisposable).Dispose()
                End If
            End Try
            Return [string]
        End Function

        Public Shared Function UnZip_deflate(compressedText As String) As String
            Dim array As Byte() = Convert.FromBase64String(compressedText)
            Dim memoryStream As MemoryStream = New MemoryStream()
            ' The following expression was wrapped in a checked-statement
            Dim [string] As String
            Try
                Dim num As Integer = BitConverter.ToInt32(array, 0)
                memoryStream.Write(array, 4, array.Length - 4)
                Dim array2 As Byte() = New Byte(num - 1 + 1 - 1) {}
                memoryStream.Position = 0L
                Dim deflateStream As DeflateStream = New DeflateStream(memoryStream, CompressionMode.Decompress)
                Try
                    deflateStream.Read(array2, 0, array2.Length)
                Finally
                    Dim flag As Boolean = deflateStream IsNot Nothing
                    If flag Then
                        CType(deflateStream, IDisposable).Dispose()
                    End If
                End Try
                [string] = Encoding.Unicode.GetString(array2, 0, array2.Length)
            Finally
                Dim flag As Boolean = memoryStream IsNot Nothing
                If flag Then
                    CType(memoryStream, IDisposable).Dispose()
                End If
            End Try
            Return [string]
        End Function

        Public Shared Function PolyDeCrypt(Data As String, Key As String, Optional ExtraRounds As UInteger = 0UI) As String
            Dim bytes As Byte() = Encoding.[Default].GetBytes(Data)
            Dim bytes2 As Byte() = DecryptAlo.PolyDeCrypt(bytes, Encoding.[Default].GetBytes(Key), ExtraRounds)
            Return Encoding.[Default].GetString(bytes2)
        End Function

        Public Shared Function PolyDeCrypt(ByRef Data As Byte(), Key As Byte(), Optional ExtraRounds As UInteger = 0UI) As Byte()
            Dim arg_11_0 As Long = 0L
            ' The following expression was wrapped in a checked-statement
            Dim num As Long = CLng((Data.Length - 1)) * CLng((CULng(ExtraRounds) + 1UL))
            Dim num2 As Long = arg_11_0
            While True
                Dim arg_5A_0 As Long = num2
                Dim num3 As Long = num
                If arg_5A_0 > num3 Then
                    Exit While
                End If
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a unchecked-expression
                ' The following expression was wrapped in a unchecked-expression
                Data(CInt((num2 Mod CLng(Data.Length)))) = CByte(((CInt(((Data(CInt((num2 Mod CLng(Data.Length)))) Xor Key(CInt((num2 Mod CLng(Key.Length))))) - Data(CInt(((num2 + 1L) Mod CLng(Data.Length)))))) + 256) Mod 256))
                num2 += 1L
            End While
            Array.Resize(Of Byte)(Data, Data.Length - 1)
            Return Data
        End Function

        Public Shared Function RijndaelDecrypt(UDecryptU As String, UKeyU As String) As Object
            Dim rijndaelManaged As RijndaelManaged = New RijndaelManaged()
            Dim salt As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
            Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(UKeyU, salt)
            rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.Key.Length)
            rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.IV.Length)
            Dim memoryStream As MemoryStream = New MemoryStream()
            Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write)
            Try
                Dim array As Byte() = Convert.FromBase64String(UDecryptU)
                cryptoStream.Write(array, 0, array.Length)
                cryptoStream.Close()
                UDecryptU = Encoding.UTF8.GetString(memoryStream.ToArray())
            Catch arg_BB_0 As Exception
                ProjectData.SetProjectError(arg_BB_0)
                ProjectData.ClearProjectError()
            End Try
            Return UDecryptU
        End Function

        Public Shared Function CustomXOR_Decrypt(Input As String, pass As String) As String
            Dim stringBuilder As StringBuilder = New StringBuilder()
            Dim mD5CryptoServiceProvider As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
            Dim array As Byte() = mD5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Dim arg_2B_0 As Integer = 0
            ' The following expression was wrapped in a checked-statement
            Dim num As Integer = Input.Length - 1
            Dim num2 As Integer = arg_2B_0
            While True
                Dim arg_8C_0 As Integer = num2
                Dim num3 As Integer = num
                If arg_8C_0 > num3 Then
                    Exit While
                End If
                Dim num4 As Integer
                ' The following expression was wrapped in a unchecked-expression
                Dim value As String = Conversions.ToString(Strings.Chr(CInt((Conversions.ToLong("&H" + Input.Substring(num2, 2)) Xor CLng((CULng(array(num4))))))))
                stringBuilder.Append(value)
                Dim flag As Boolean = num4 = pass.Length - 1
                If flag Then
                    num4 = 0
                Else
                    num4 += 1
                End If
                num2 += 2
            End While
            Return stringBuilder.ToString()
        End Function

        Public Shared Function BASE64_Decrypt(input As String) As String
            Return Encoding.ASCII.GetString(Convert.FromBase64String(input))
        End Function

        Public Shared Function Pr0t3_DecrypT(Decrypt As String) As Object
            Dim num As Integer = 3
            Dim i As Integer = 0
            Dim length As Integer = Decrypt.Length
            ' The following expression was wrapped in a checked-statement
            Dim text As String
            While i < length
                Dim [string] As Char = Decrypt(i)
                text += Conversions.ToString(Strings.Chr(Strings.Asc([string]) - num))
                i += 1
            End While
            text = Strings.StrReverse(text)
            Return text
        End Function
    End Class
End Namespace
