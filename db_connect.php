<?php

	$conn = mysqli_connect("localhost", "root", "", "datadummy");

	if(mysqli_connect_error()){
		echo "Database gagal diakses";
	}

	function error($message) {
        
        // Display the alert box 
        echo "<script>alert('$message')</script>";
    }


	function registrasi($data){
		global $conn;

		$nama = $data["nama"];
		$nama=(filter_var($nama,  FILTER_SANITIZE_STRING));
		$email = $data["email"];
		$email=(filter_var($email,  FILTER_SANITIZE_EMAIL));
		$password = mysqli_real_escape_string($conn, $data["password"]);
		$password2 = mysqli_real_escape_string($conn, $data["password2"]);

		$stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");

		if (!$stmt) {
			die('Query Error : '.$mysqli->errno.
			' - '.$mysqli->error);
		}

		$stmt->bind_param("s", $email);
		$stmt->execute();
		$result = $stmt->get_result();

		// $result = mysqli_query($conn, "SELECT email FROM users WHERE email = '$email' ");
		if(mysqli_fetch_assoc($result)){
			error("Email telah terdaftar!");
			return false;
		}

		if($password !== $password2){
			error("Konfirmasi password tidak sesuai");
			return false;
		}

		$password = password_hash($password, PASSWORD_DEFAULT);

		$stmt = $conn->prepare("INSERT INTO users (nama, email, password) VALUES (?, ?, ?)");
		$stmt->bind_param("sss", $nama, $email, $password);
		$stmt->execute();
		
		return mysqli_affected_rows($conn);
		$stmt->close();
		$conn->close();
	}


?>