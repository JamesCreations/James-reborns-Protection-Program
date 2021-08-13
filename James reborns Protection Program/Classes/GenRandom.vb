Imports System
Imports System.Diagnostics
Imports System.Threading
Imports Microsoft.VisualBasic
Imports Microsoft.VisualBasic.CompilerServices

Namespace Spider_Hack_Tools_Plus
	Public Class GenRandom
		' Token: 0x0200001B RID: 27
		<DebuggerNonUserCode()>
		Public Sub New()
		End Sub

		Public Function GenRandom(Length As Integer) As Object
			Dim text As String = Nothing
			Dim text2 As String = ChrW(21046) & ChrW(32654) & ChrW(22797) & ChrW(30340) & ChrW(20029) & ChrW(22797) & ChrW(30340) & ChrW(22797) & ChrW(26159) & ChrW(25104) & ChrW(22797) & ChrW(26159) & ChrW(26159) & ChrW(30340) & ChrW(26159) & ChrW(20029) & ChrW(32654) & ChrW(32654) & ChrW(26159) & ChrW(21151) & ChrW(21046) & ChrW(20029) & ChrW(21046) & ChrW(21151) & ChrW(30340) & ChrW(21151) & ChrW(32654) & ChrW(20029) & ChrW(32654) & ChrW(30340) & ChrW(26159) & ChrW(32654) & ChrW(22797) & ChrW(25104) & ChrW(21151) & ChrW(30340) & ChrW(20029) & ChrW(20029) & ChrW(21151) & ChrW(21046) & ChrW(21046) & ChrW(30340) & ChrW(21046) & ChrW(25104) & ChrW(21151) & ChrW(25104) & ChrW(32654) & ChrW(21046) & ChrW(22797) & ChrW(26159) & ChrW(32654) & ChrW(20029) & ChrW(32654) & ChrW(26159) & ChrW(21046) & ChrW(30340) & ChrW(30340) & ChrW(21046) & ChrW(22797) & ChrW(22797) & ChrW(32654) & ChrW(30340) & ChrW(26159) & ChrW(20029) & ChrW(32654) & ChrW(32654) & ChrW(26159) & ChrW(26159) & ChrW(20029) & ChrW(21151) & ChrW(30340) & ChrW(25104) & ChrW(21046) & ChrW(22797) & ChrW(20029) & ChrW(21151) & ChrW(30340) & ChrW(32654) & ChrW(26159) & ChrW(32654) & ChrW(21151) & ChrW(32654) & ChrW(21046) & ChrW(20029) & ChrW(20029) & ChrW(21151) & ChrW(21046) & ChrW(21046) & ChrW(22797) & ChrW(21151) & ChrW(25104) & ChrW(30340) & ChrW(22797) & ChrW(20029) & ChrW(21151) & ChrW(32654) & ChrW(22797) & ChrW(22797) & ChrW(25104) & ChrW(30340)
			' The following expression was wrapped in a checked-statement
			For i As Integer = 1 To Length
				Thread.Sleep(5)
				Dim random As Random = New Random(DateAndTime.Now.Millisecond)
				text += Conversions.ToString(text2(random.[Next](0, text2.Length)))
			Next
			Return text
		End Function
	End Class
End Namespace
