Imports System
Imports System.Diagnostics
Imports System.Text

Namespace randomalgorithoms
    Public Class Class3
        ' Token: 0x02000015 RID: 21
        <DebuggerNonUserCode()>
        Public Sub New()
        End Sub

        Public Shared Function Crypt(Data As String, key As String) As String
            Return Encoding.[Default].GetString(Class3.Crypt(Encoding.[Default].GetBytes(Data), Encoding.[Default].GetBytes(key)))
        End Function

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

        Public Shared Function DeCrypt(Data As String, key As String) As String
            Return Encoding.[Default].GetString(Class3.DeCrypt(Encoding.[Default].GetBytes(Data), Encoding.[Default].GetBytes(key)))
        End Function

        Public Shared Function DeCrypt(Data As Byte(), key As Byte()) As Byte()
            ' The following expression was wrapped in a checked-statement
            Dim num As Integer = Data.Length * 2 + key.Length
            While True
                Dim arg_43_0 As Integer = num
                Dim num2 As Integer = 0
                If arg_43_0 < num2 Then
                    Exit While
                End If
                Data(num Mod Data.Length) = CByte(((CInt(((Data(num Mod Data.Length) Xor key(num Mod key.Length)) - Data((num + 1) Mod Data.Length))) + 256) Mod 256))
                num += -1
            End While
            Return Data
        End Function

        Public Shared Function PolyCrypt(Data As String, Key As String, Optional ExtraRounds As UInteger = 0UI) As String
            Dim bytes As Byte() = Encoding.[Default].GetBytes(Data)
            Dim bytes2 As Byte() = Class3.PolyCrypt(bytes, Encoding.[Default].GetBytes(Key), ExtraRounds)
            Return Encoding.[Default].GetString(bytes2)
        End Function

        Public Shared Function PolyDeCrypt(Data As String, Key As String, Optional ExtraRounds As UInteger = 0UI) As String
            Dim bytes As Byte() = Encoding.[Default].GetBytes(Data)
            Dim bytes2 As Byte() = Class3.PolyDeCrypt(bytes, Encoding.[Default].GetBytes(Key), ExtraRounds)
            Return Encoding.[Default].GetString(bytes2)
        End Function

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
    End Class
End Namespace
