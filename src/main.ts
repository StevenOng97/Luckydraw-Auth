import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.connectMicroservice({
    transport: Transport.TCP,
    options: {
      host: 'localhost',
      port: 4000,
    },
  });
  app.enableCors({
    origin: '*',
  });

  const config = new DocumentBuilder()
    .setTitle('Lucky Draw Auth Service')
    .setDescription('Lucky Draw Auth Service API description')
    .setVersion('1.0')
    .addTag('luckydrawauth')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.startAllMicroservices();
  await app.listen(8000);
  Logger.log('Auth microservice running');
}
bootstrap();
