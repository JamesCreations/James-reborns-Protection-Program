Imports System
Imports System.Diagnostics
Imports Microsoft.VisualBasic
Public Class vernam1
    ' Token: 0x02000042 RID: 66
    <DebuggerNonUserCode()>
    Public Sub New()
    End Sub

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
End Class
