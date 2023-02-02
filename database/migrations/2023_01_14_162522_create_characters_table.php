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
        Schema::create('characters', function (Blueprint $table) {
              /* the primary key of the post */
              $table->increments('id');

              /* the title of the post */
              $table->string('name');
  
              /* the time when the post is fetched */
              $table->timestamp('created_at'); /* NOTE: column is changed to timestamp here */
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('characters');
    }
};
