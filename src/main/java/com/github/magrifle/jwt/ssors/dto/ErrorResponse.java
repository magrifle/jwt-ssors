package com.github.magrifle.jwt.ssors.dto;

import java.io.Serializable;

public class ErrorResponse implements Serializable
{
    private String status;

    private String message;


    public ErrorResponse(String message)
    {
        this.message = message;
        this.status = "Failed";
    }


    public String getStatus()
    {
        return status;
    }


    public String getMessage()
    {
        return message;
    }


}

