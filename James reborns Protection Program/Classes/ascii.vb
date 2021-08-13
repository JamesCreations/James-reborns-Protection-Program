Imports System
Imports System.Diagnostics
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices

Namespace Crypter
	Public Class ascii
		' Token: 0x02000008 RID: 8
		<DebuggerNonUserCode()>
		Public Sub New()
		End Sub

		Public Class asciii
			' Token: 0x02000009 RID: 9
			<DebuggerNonUserCode()>
			Public Sub New()
			End Sub

			Public Class VigenereCipher
				' Token: 0x0200000A RID: 10
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
						Dim arg_54_0 As Integer = num
						Dim num2 As Integer = length
						If arg_54_0 > num2 Then
							Exit While
						End If
						Dim charCode As Integer = Strings.Asc(Strings.GetChar(cipherTxt, num)) + Strings.Asc(Strings.GetChar(key, num Mod key.Length + 1))
						text += Conversions.ToString(Strings.Chr(charCode))
						num += 1
					End While
					Return text
				End Function

				Public Shared Function Decrypt(cipherTxt As String, key As String) As Object
					Dim text As String = ""
					Dim arg_10_0 As Integer = 1
					Dim length As Integer = cipherTxt.Length
					Dim num As Integer = arg_10_0
					' The following expression was wrapped in a checked-statement
					While True
						Dim arg_54_0 As Integer = num
						Dim num2 As Integer = length
						If arg_54_0 > num2 Then
							Exit While
						End If
						Dim charCode As Integer = Strings.Asc(Strings.GetChar(cipherTxt, num)) - Strings.Asc(Strings.GetChar(key, num Mod key.Length + 1))
						text += Conversions.ToString(Strings.Chr(charCode))
						num += 1
					End While
					Return text
				End Function
			End Class
		End Class
	End Class
End Namespace
