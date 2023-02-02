<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('votes', function (Blueprint $table) {
            $table->integer('user_id')->unsigned();


            $table->integer('character_id')->unsigned();


            $table->timestamp('created_at');

        
            $table->foreign('user_id')->references('id')->on('users')
                ->onDelete('cascade')->onUpdate('cascade');


            $table->foreign('character_id')->references('id')->on('characters')
                ->onDelete('cascade')->onUpdate('cascade');
        });
    }

  
    public function down()
    {
        Schema::dropIfExists('votes');
    }
};
