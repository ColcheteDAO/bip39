let innerHTML = ""
innerHTML += `<table class='table'>
                <thead>
                  <tr>
                    <th>index</th>
                    <th>word</th>
                    <th>bin</th>
                    <th>oct</th>
                    <th>hex</th>
                    <th>| 1 | 2 | 4 | 8 |</th>
                  </tr>
                </thead>`
for (let i = 0; i < WORDLISTS["english"].length; i++) {
  innerHTML += `<tbody>
                  <tr>
                    <td>${i}</td>
                    <td>${WORDLISTS["english"][i]}</td>
                    <td>${i.toString(2)}</td>
                    <td>${i.toString(8)}</td>
                    <td>0x${i.toString(16)}</td>
                    <td><table><td style="background-color: #e29f51;">${calculateSteelPattern(i, 0)}</td><td style="background-color: #ffb55a;">${calculateSteelPattern(i, 1)}</td><td style="background-color: #e29f51;">${calculateSteelPattern(i, 2)}</td><td style="background-color: #ffb55a;">${calculateSteelPattern(i, 3)}</td></table></td>
                  </tr>
                </tbody>`
}
innerHTML += "</table>"
document.getElementById("wordsTable").innerHTML = innerHTML

function calculateSteelPattern(i, index) {
  let steelPattern = ["0️⃣", "0️⃣ </br>", "0️⃣", "0️⃣"]
  markedSum = parseInt(i.toString().padStart(4, '0')[index]);
  if (markedSum >= 8) {
    markedSum -= 8
    steelPattern[3] = "8️⃣"
  }
  if (markedSum >= 4) {
    markedSum -= 4
    steelPattern[2] = "4️⃣"
  }
  if (markedSum >= 2) {
    markedSum -= 2
    steelPattern[1] = "2️⃣ </br>"
  }
  if (markedSum >= 1) {
    markedSum -= 1
    steelPattern[0] = "1️⃣"
  }
  if (index == 0) {
    steelPattern = steelPattern.slice(0, 2)
    steelPattern[1] = steelPattern[1].replace(" </br>", "")
    steelPattern[0] += "</br>"
  }
  return steelPattern.toString().replaceAll(",", "");

}
