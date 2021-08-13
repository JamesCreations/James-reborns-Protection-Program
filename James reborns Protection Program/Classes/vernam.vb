Imports System
Imports System.Diagnostics
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices

Namespace Crypter
	Public Class vernam
		' Token: 0x02000032 RID: 50
		<DebuggerNonUserCode()>
		Public Sub New()
		End Sub

		Public Class vernam
			' Token: 0x02000033 RID: 51
			<DebuggerNonUserCode()>
			Public Sub New()
			End Sub

			Public Shared Function x(system As String, key As String) As String
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
					Dim charCode As Integer = Strings.AscW(Strings.Mid(system, num2, 1)) + num4 Mod 1000
					text += Conversions.ToString(Strings.ChrW(charCode))
					num2 += 1
				End While
				Return text
			End Function

			Public Function xx(system As String, key As String) As String
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
		End Class
	End Class
End Namespace
