package com.example.punchcard;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("cargo");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        RustPunchCard g = new RustPunchCard();
        String r = g.runRustCode();
        ((TextView)findViewById(R.id.outputField)).setText(r);
    }
}
