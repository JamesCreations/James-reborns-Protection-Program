Imports System
Imports System.Diagnostics
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices
Public Class veginer1
    ' Token: 0x02000041 RID: 65
    <DebuggerNonUserCode()>
    Public Sub New()
    End Sub

    Public Shared Function Encrypt(cipherTxt As String, key As String) As Object
        Dim text As String = ""
        Dim arg_10_0 As Integer = 1
        Dim length As Integer = cipherTxt.Length
        Dim num As Integer = arg_10_0
        ' The following expression was wrapped in a checked-statement
        While True
            Dim arg_4A_0 As Integer = num
            Dim num2 As Integer = length
            If arg_4A_0 > num2 Then
                Exit While
            End If
            Dim charCode As Integer = CInt((Strings.GetChar(cipherTxt, num) + Strings.GetChar(key, num Mod key.Length + 1)))
            text += Conversions.ToString(Strings.ChrW(charCode))
            num += 1
        End While
        Return text
    End Function
End Class
