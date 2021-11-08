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
		$email = $data["email"];
		$password = mysqli_real_escape_string($conn, $data["password"]);
		$password2 = mysqli_real_escape_string($conn, $data["password2"]);

		$result = mysqli_query($conn, "SELECT email FROM users WHERE email = '$email' ");
		if(mysqli_fetch_assoc($result)){
			error("Email telah terdaftar!");
			return false;
		}

		if($password !== $password2){
			error("Konfirmasi password tidak sesuai");
			return false;
		}

		$password = password_hash($password, PASSWORD_DEFAULT);

		mysqli_query($conn, "INSERT INTO users VALUES('', '$nama', '$email', '$password')");

		return mysqli_affected_rows($conn);

	}


?>