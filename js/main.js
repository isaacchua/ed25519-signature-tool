/**
 * @file Provides the functionality of Ed25519.html.
 * @author Isaac Chua
 * @version 1.1.1
 * @copyright 2019-2024 Isaac Chua
 * @license MIT
 */

(function (global, factory) {
	if (typeof global !== 'undefined' // check for window object
		&& typeof global.jQuery !== 'undefined' // check for jQuery
		&& typeof global.sodium !== 'undefined' // check for libsodium
		&& typeof global.ed25519 === 'undefined' // prevent double load
	) global.ed25519 = factory();
}(this, function () { "use strict";

	const TEST_SECRET_JWK = '{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
	const TEST_PUBLIC_JWK = '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
	const TEST_JWK_THUMBPRINT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
	const TEST_JWS_PROTECTED_HEADER = '{"alg":"EdDSA"}';
	const TEST_JWS_PAYLOAD = 'Example of Ed25519 signing';
	const TEST_JWS_SIGNING_INPUT = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
	const TEST_JWS_SIGNATURE = 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';
	const TEST_JWS_COMPACT_SERIALISED = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

	const JWK_THUMBPRINT_ED25519_MEMBERS = ['crv','kty','x'];
	const YEAR_SECONDS = 31536000;

	function isUndefined(value) {
		return value === void(0);
	}

	function alertAndLog(message) {
		alert(message);
		console.log(message);
	}

	function getPublicKey() {
		let publicKey = $("#publicKey").val();
		if (publicKey === "") {
			alertAndLog("Public JWK is empty.");
			return false;
		}
		return getKey(publicKey, false);
	}

	function getSecretKey() {
		let secretKey = $("#secretKey").val();
		if (secretKey === "") {
			alertAndLog("Secret JWK is empty.");
			return false;
		}
		return getKey($("#secretKey").val(), true);
	}

	function getKey (json, isSecret) {
		let keyType = isSecret ? "secret" : "public";
		try {
			let jwk = JSON.parse(json);

			// check key type
			if (jwk["kty"] !== "OKP") {
				alertAndLog("Unknown Ed25519 " + keyType + " JWK kty: " + jwk["kty"]);
				return;
			}
			// check curve
			if (jwk["crv"] !== "Ed25519") {
				alertAndLog("Unknown Ed25519 " + keyType + " JWK kty: " + jwk["crv"]);
				return;
			}
			// check public key
			if (isUndefined(jwk["x"])) {
				alertAndLog("Undefined Ed25519 " + keyType + " JWK x.");
				return;
			}
			let x_b = sodium.from_base64(jwk["x"], sodium.base64_variants.URLSAFE_NO_PADDING);
			if (!(x_b instanceof Uint8Array && x_b.length === 32)) {
				alertAndLog("Invalid Ed25519 " + keyType + " JWK x: " + jwk["x"]);
				return;
			}
			jwk["x_b"] = x_b;
			// check secret key
			if (isSecret) {
				if (isUndefined(jwk["d"])) {
					alertAndLog("Undefined Ed25519 " + keyType + " JWK d.");
					return;
				}
				let d_b = sodium.from_base64(jwk["d"], sodium.base64_variants.URLSAFE_NO_PADDING);
				if (!(d_b instanceof Uint8Array && d_b.length === 32)) {
					alertAndLog("Invalid Ed25519 " + keyType + " JWK d: " + jwk["d"]);
					return;
				}
				jwk["d_b"] = d_b;

				// generate combined secret+public key for libsodium's use
				let dx_b = new Uint8Array(64);
				dx_b.set(d_b, 0);
				dx_b.set(x_b, 32);
				jwk["dx_b"] = dx_b;
			}
			return jwk;
		}
		catch (e) {
			if (e instanceof SyntaxError) {
				alert("Invalid Ed25519 " + keyType + " JWK JSON.");
			}
			console.log(e);
		}
	}

	function calculateThumbprint (publicKey) {
		let sorted = sortMembers(publicKey); // sort members per RFC 7638
		let input = JSON.stringify(sorted, JWK_THUMBPRINT_ED25519_MEMBERS); // select mandatory members and convert to JSON per RFC 7638 and RFC 8037
		let sha256 = sodium.crypto_hash_sha256(input); // use SHA-256 as recommended by RFC 7638
		return sodium.to_base64(sha256, sodium.base64_variants.URLSAFE_NO_PADDING);
	}

	function sortMembers (o) {
		return Object.keys(o).sort().reduce((r, k) => (r[k] = o[k], r), {});
	}

	function validateJwsProtectedHeader (value) {
		try {
			let header = JSON.parse(value);
			if (isUndefined(header["alg"])) {
				alertAndLog("JWS protected header does not contain required parameter: alg");
				return false;
			}
			if (header["alg"] !== "EdDSA") {
				alertAndLog("JWS protected header specifies unrecognised alg: " + header["alg"]);
			}
			return true;
		}
		catch (e) {
			if (e instanceof SyntaxError) {
				alert("Invalid JWS protected header JSON.");
			}
			console.log(e);
		}
		return false;
	}

	function testJws () {
		// get public key
		let publicKey = getPublicKey();
		if (isUndefined(publicKey)) return false;

		// process JWS into its parts
		let parts = $("#jwsCompactSerialized").val().split(".");
		if (parts.length !== 3) {
			alertAndLog("Parts of JWS not exactly 3: " + parts.length);
			return false;
		}
		try {
			// verify header
			let jwsProtectedHeader = sodium.to_string(sodium.from_base64(parts[0], sodium.base64_variants.URLSAFE_NO_PADDING));
			if (!validateJwsProtectedHeader(jwsProtectedHeader)) return false;

			// put together signing input
			let signingInput = parts[0] + "." + parts[1];

			// retrieve signature
			let signature = sodium.from_base64(parts[2], sodium.base64_variants.URLSAFE_NO_PADDING);

			// verify signature
			try {
				return sodium.crypto_sign_verify_detached(signature, signingInput, publicKey["x_b"]);
			}
			catch (e) {
				console.log(e);
				return false;
			}
		}
		catch (e) {
			alert ("Unable to parse JWS.")
			console.log(e);
			return false;
		}
	}

	function runVectorTests (e) {
		console.log("Testing secret JWK");
		$("#secretKey").val(TEST_SECRET_JWK);
		let secretKey = getSecretKey();
		if (isUndefined(secretKey)) return false;

		console.log("Testing public JWK");
		$("#publicKey").val(TEST_PUBLIC_JWK);
		let publicKey = getPublicKey();
		if (isUndefined(publicKey)) return false;

		console.log("Testing JWK thumbprint");
		if (!generateThumbprint()) return false;
		if ($("#jwkThumbprint").val() !== TEST_JWK_THUMBPRINT) {
			alertAndLog("Calculated JWK thumbprints do not match.");
			return false;
		}

		console.log("Testing JWS protected header, payload, and signing input");
		$("#jwsProtectedHeader").val(TEST_JWS_PROTECTED_HEADER);
		$("#jwsPayload").val(TEST_JWS_PAYLOAD);
		if (!generateSigningInput()) return false;
		if ($("#signingInput").val() !== TEST_JWS_SIGNING_INPUT) {
			alertAndLog("Calculated JWS signing inputs do not match.");
			return false;
		}

		console.log("Testing JWS signature");
		if (!generateSignature()) return false;
		if ($("#signatureOutput").val() !== TEST_JWS_SIGNATURE) {
			alertAndLog("Calculated JWS signature outputs do not match.");
			return false;
		}
		if ($("#jwsCompactSerialized").val() !== TEST_JWS_COMPACT_SERIALISED) {
			alertAndLog("Calculated JWS outputs do not match.");
			return false;
		}

		console.log("Validating JWS signature");
		if (testJws()) {
			alertAndLog("All tests passed.");
		}
		else {
			alertAndLog("JWS output is not valid.");
		}
	}

	function runGeneratorTests (e) {
		console.log("Generating keypair");
		if (!generateKeypair()) {
			alertAndLog("Unable to generate keypair.");
		}

		console.log("Testing JWS protected header, payload, and signing input");
		$("#jwsProtectedHeader").val(TEST_JWS_PROTECTED_HEADER);
		$("#jwsPayload").val(TEST_JWS_PAYLOAD);
		if (!generateSigningInput()) return false;
		if ($("#signingInput").val() !== TEST_JWS_SIGNING_INPUT) {
			alertAndLog("Calculated JWS signing inputs do not match.");
			return false;
		}

		console.log("Testing and validating JWS signature");
		if (generateThumbprint() && generateInputAndSignature() && testJws()) {
			alertAndLog("All tests passed.");
		}
		else {
			alertAndLog("Unable to test and validate JWS signature.");
		}
	}

	function generateKeypair (e) {
		// generate the keypair depending on whether a seed is provided
		let generatedKeypair;
		if ($("#useSeed").prop("checked")) {
			try {
				let seed = sodium.from_base64($("#keySeed").val(), sodium.base64_variants.URLSAFE_NO_PADDING);
				if (seed.length !== sodium.crypto_sign_SEEDBYTES) {
					alertAndLog("Seed provided is not exactly " + sodium.crypto_sign_SEEDBYTES + " bytes.");
					return false;
				}
				generatedKeypair = sodium.crypto_sign_seed_keypair(seed);
			}
			catch (ex) {
				alert("Invalid seed.");
				console.log(ex);
				return false;
			}
		}
		else {
			generatedKeypair = sodium.crypto_sign_keypair();
		}

		// retrieve the keys
		let x_b = generatedKeypair.publicKey;
		let dx_b = generatedKeypair.privateKey;
		let d_b = dx_b.slice(0, 32);
		let x = sodium.to_base64(x_b, sodium.base64_variants.URLSAFE_NO_PADDING);
		let d = sodium.to_base64(d_b, sodium.base64_variants.URLSAFE_NO_PADDING);
		let secretKey = '{"kty":"OKP","crv":"Ed25519","d":"' + d + '","x":"' + x + '"';
		let publicKey = '{"kty":"OKP","crv":"Ed25519","x":"' + x + '"';

		// check for and include dates
		if ($("#includeDates").prop("checked")) {
			let iat = Math.round((new Date()).getTime() / 1000);
			let years = parseFloat($("#expiryYears").val());
			if (isNaN(years)) {
				alertAndLog("Invalid number of expiry years.");
				return false;
			}
			if (years <= 0) {
				alertAndLog("Expiry years must be a positive number.");
				return false;
			}
			let exp = iat + Math.round(years * YEAR_SECONDS);
			secretKey += ',"iat":' + iat + ',"exp":' + exp;
			publicKey += ',"iat":' + iat + ',"exp":' + exp;
		}

		// complete the JWKs
		secretKey += '}';
		publicKey += '}';

		// set the field values
		$("#secretKey").val(secretKey);
		$("#publicKey").val(publicKey);
		clearThumbprintField();
		clearSignatureFields();
		$("#jwsCompactSerialized").val("");
		return true;
	}

	function generateThumbprint (e) {
		let publicKey = getPublicKey();
		if (isUndefined(publicKey)) return false;

		let thumbprint = calculateThumbprint(publicKey);
		$("#jwkThumbprint").val(thumbprint);
		return true;
	}

	function generateInputAndSignature (e) {
		return generateSigningInput(e) && generateSignature(e);
	}

	function generateSigningInput (e) {
		let jwsProtectedHeader = $("#jwsProtectedHeader").val();
		if (!validateJwsProtectedHeader(jwsProtectedHeader)) return false;
		let signingInput =
			sodium.to_base64(jwsProtectedHeader, sodium.base64_variants.URLSAFE_NO_PADDING) +
			"." +
			sodium.to_base64($("#jwsPayload").val(), sodium.base64_variants.URLSAFE_NO_PADDING);
		$("#signingInput").val(signingInput);
		return true;
	}

	function generateSignature (e) {
		let secretKey = getSecretKey();
		if (isUndefined(secretKey)) return false;

		let signingInput = $("#signingInput").val();
		let signature = sodium.crypto_sign_detached(signingInput, secretKey["dx_b"]);
		let signatureBase64 = sodium.to_base64(signature, sodium.base64_variants.URLSAFE_NO_PADDING);
		$("#signatureOutput").val(signatureBase64);
		$("#jwsCompactSerialized").val(signingInput + "." + signatureBase64);
		return true;
	}

	function deconstructJws (e) {
		// process JWS into its parts
		let parts = $("#jwsCompactSerialized").val().split(".");
		if (parts.length !== 3) {
			alertAndLog("Parts of JWS not exactly 3: " + parts.length);
			return false;
		}
		try {
			// decode header
			let jwsProtectedHeader = sodium.to_string(sodium.from_base64(parts[0], sodium.base64_variants.URLSAFE_NO_PADDING));

			// decode payload
			let jwsPayload = sodium.to_string(sodium.from_base64(parts[1], sodium.base64_variants.URLSAFE_NO_PADDING));

			// set data
			$("#jwsProtectedHeader").val(jwsProtectedHeader);
			$("#jwsPayload").val(jwsPayload);
		}
		catch (e) {
			alert ("Unable to parse JWS.")
			console.log(e);
			return false;
		}
	}

	function validateJws (e) {
		if (testJws()) {
			alertAndLog("JWS is valid.");
			return true;
		}
	}

	function clearThumbprintField (e) {
		$("#jwkThumbprint").val("");
		return true;
	}

	function clearSignatureFields (e) {
		$("#signingInput").val("");
		$("#signatureOutput").val("");
		return true;
	}

	function setInputDisabled (e) {
		e.data.prop("disabled", !e.currentTarget.checked);
	}

	$(document).ready(function () {
		$("#runVectorTests").click(runVectorTests);
		$("#runGeneratorTests").click(runGeneratorTests);
		$("#generateKeypair").click(generateKeypair);
		$("#generateThumbprint").click(generateThumbprint);
		$("#generateInputAndSignature").click(generateInputAndSignature);
		$("#deconstructJws").click(deconstructJws);
		$("#validateJws").click(validateJws);
		$("#publicKey").change(clearThumbprintField);
		$("#jwsProtectedHeader").change(clearSignatureFields);
		$("#jwsPayload").change(clearSignatureFields);
		$("#jwsCompactSerialized").change(clearSignatureFields);
		$(".seed-length").html(sodium.crypto_sign_SEEDBYTES);
		$("#useSeed").on("click", $("#keySeed"), setInputDisabled);
		$("#includeDates").on("click", $("#expiryYears"), setInputDisabled);
	});

	return {
		getPublicKey: getPublicKey
	};
}));
