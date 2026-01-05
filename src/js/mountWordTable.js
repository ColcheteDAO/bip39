let innerHTML = ""
signal = "🟩🟥" 
innerHTML += "<table class='table'><thead><tr><th>index</th><th>word</th><th>bin</th><th>oct</th><th>hex</th><th>| 1 | 2 | 4 | 8 |</th><th>| 1 | 2 | 4 | 8 |</th><th>| 1 | 2 | 4 | 8 |</th><th>| 1 | 2 | 4 | 8 |</th></tr></thead>"
for (let i=0;i < WORDLISTS["english"].length; i++){
innerHTML += `<tbody><tr><td>${i}</td>`
innerHTML += `<td>${WORDLISTS["english"][i]}</td>`
innerHTML += `<td>${i.toString(2)}</td>`
innerHTML += `<td>${i.toString(8)}</td>`
innerHTML += `<td>0x${i.toString(16)}</td>`
steelPattern = calculateSteelPattern(i,0) 
innerHTML += `<td>${steelPattern}</td>`
steelPattern = calculateSteelPattern(i,1) 
innerHTML += `<td>${steelPattern}</td>`
steelPattern = calculateSteelPattern(i,2) 
innerHTML += `<td>${steelPattern}</td>`
steelPattern = calculateSteelPattern(i,3) 
innerHTML += `<td>${steelPattern}</td></tr></tbody>`
}
innerHTML += "</table>"
document.getElementById("wordsTable").innerHTML = innerHTML

function calculateSteelPattern(i,index){
  let steelPattern = ["🟥","🟥","🟥","🟥"]
  markedSum = parseInt(i.toString().padStart(4, '0')[index]);
  console.log(`${i} ${index} ${markedSum} ${i.toString().padStart(4, '0')}`)
  if(markedSum >= 8){
    markedSum -= 8
    steelPattern[3] = "🟩"
  }
  if(markedSum >= 4){
    markedSum -= 4
    steelPattern[2] = "🟩"
  }
  if(markedSum >= 2){
    console.log("here")
    markedSum -= 2
    steelPattern[1] = "🟩"
  }
  if(markedSum >= 1){
    markedSum -= 1
    steelPattern[0] = "🟩"
  }  
  return steelPattern.toString().replaceAll(",","");
  
}
