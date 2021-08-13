Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Imports System.Windows

Public Class cTripleDES
    ' Token: 0x02000018 RID: 24

    Public Shared key As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}

    Public Shared iv As Byte() = New Byte() {33, 9, 22, 45, 11, 1, 6, 30, 15}

    Public Shared des As cTripleDES = New cTripleDES(key, iv)
    Public Sub New(key As Byte(), iv As Byte())
        Me.m_des = New TripleDESCryptoServiceProvider()
        Me.m_utf8 = New UTF8Encoding()
        Me.m_key = key
        Me.m_iv = iv
    End Sub

    Public Function Encrypt(input As Byte()) As Byte()
        Return cTripleDES.Transform(input, Me.m_des.CreateEncryptor(Me.m_key, Me.m_iv))
    End Function

    Public Shared Function Transform(input As Byte(), CryptoTransform As ICryptoTransform) As Byte()
        Dim memoryStream As MemoryStream = New MemoryStream()
        Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, CryptoTransform, CryptoStreamMode.Write)
        cryptoStream.Write(input, 0, input.Length)
        cryptoStream.FlushFinalBlock()
        memoryStream.Position = 0L
        ' The following expression was wrapped in a checked-expression
        Dim array As Byte() = New Byte(CInt((memoryStream.Length - 1L)) + 1 - 1) {}
        memoryStream.Read(array, 0, array.Length)
        memoryStream.Close()
        cryptoStream.Close()
        Return array
    End Function

    Private m_des As TripleDESCryptoServiceProvider

    Private m_utf8 As UTF8Encoding

    Private m_key As Byte()

    Private m_iv As Byte()
End Class
